#!/usr/bin/env bash
# forensic-scan.sh - automated triage of EBS evidence volumes on the forensic workstation.
#
# Invoked by the Step Functions workflow through SSM Run Command:
#   forensic-scan.sh --case-id CASE-... --bucket <evidence-bucket> --kms-key-id <arn> \
#                    --region us-east-1 --volumes vol-analysis1:vol-source1,vol-analysis2:vol-source2
#
# For every attached analysis volume it:
#   1. sets the block device read-only (software write blocker)
#   2. hashes the full raw device with SHA-256 (image integrity / chain of custody)
#   3. mounts each filesystem read-only (noexec,nodev,nosuid, no journal replay)
#   4. builds a filesystem timeline (Sleuth Kit fls/mactime, plus a find-based timeline)
#   5. scans with ClamAV and YARA
#   6. collects persistence / auth artifacts (cron, systemd, ssh keys, shell history, logs)
#   7. flags suspicious files (SUID, executables in tmp dirs, hidden executables, recent changes)
# then writes report.md + summary.json, hashes every output file and uploads
# everything to s3://<bucket>/cases/<case-id>/analysis/ with SSE-KMS.
set -Eeuo pipefail

CASE_ID="" BUCKET="" KMS_KEY_ID="" REGION="" VOLUMES="" RECENT_DAYS="${RECENT_DAYS:-14}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --case-id) CASE_ID="$2"; shift 2 ;;
    --bucket) BUCKET="$2"; shift 2 ;;
    --kms-key-id) KMS_KEY_ID="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    --volumes) VOLUMES="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
[[ "$CASE_ID" =~ ^[A-Za-z0-9-]{6,64}$ ]] || { echo "invalid case id" >&2; exit 2; }
[[ -n "$BUCKET" && -n "$KMS_KEY_ID" && -n "$REGION" && -n "$VOLUMES" ]] || { echo "missing arguments" >&2; exit 2; }

export PATH="$PATH:/snap/bin:/usr/local/bin"
RULES_DIR=/opt/forensics/rules
WORK="/forensics/cases/${CASE_ID}"
OUT="${WORK}/analysis"
MNT_ROOT="/mnt/evidence/${CASE_ID}"
rm -rf "$WORK"
mkdir -p "$OUT" "$MNT_ROOT"
chmod 700 "$WORK"
exec > >(tee -a "${OUT}/scan.log") 2>&1

log() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*"; }
MOUNTS=()
cleanup_mounts() {
  for m in "${MOUNTS[@]:-}"; do [[ -n "$m" ]] && umount "$m" 2>/dev/null || true; done
}
trap cleanup_mounts EXIT

log "Case ${CASE_ID}: starting forensic scan on $(hostname) ($(uname -r))"
{
  echo "sleuthkit=$(fls -V 2>/dev/null | head -1 || echo n/a)"
  echo "clamav=$(clamscan --version 2>/dev/null || echo n/a)"
  echo "yara=$(yara --version 2>/dev/null || echo n/a)"
  echo "scan_script_sha256=$(sha256sum "$0" | cut -d' ' -f1)"
  echo "rules_sha256=$(cat "$RULES_DIR"/*.yar 2>/dev/null | sha256sum | cut -d' ' -f1)"
} > "${OUT}/tool-versions.txt"

cat "$RULES_DIR"/*.yar > "${WORK}/combined-rules.yar" 2>/dev/null || true

find_device() {
  # EBS volumes on Nitro instances appear as NVMe devices whose serial is the volume id without the dash.
  local vol="$1" serial="${1/-/}" dev=""
  for _ in $(seq 1 60); do
    if [[ -e "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${serial}" ]]; then
      dev=$(readlink -f "/dev/disk/by-id/nvme-Amazon_Elastic_Block_Store_${serial}"); break
    fi
    dev=$(lsblk -dnpo NAME,SERIAL | awk -v s="$serial" '$2==s {print $1}' | head -1)
    [[ -n "$dev" ]] && break
    sleep 5
  done
  [[ -n "$dev" ]] || { log "device for $vol not found"; return 1; }
  echo "$dev"
}

mount_opts() {
  case "$1" in
    ext2|ext3|ext4) echo "ro,noexec,nodev,nosuid,noload" ;;
    xfs) echo "ro,noexec,nodev,nosuid,norecovery,nouuid" ;;
    vfat|ntfs|ntfs3) echo "ro,noexec,nodev,nosuid" ;;
    *) echo "" ;;
  esac
}

analyse_filesystem() {
  local part="$1" fstype="$2" dest="$3" mnt="$4"
  mkdir -p "$dest" "$mnt"
  blockdev --setro "$part" || true

  log "  timeline (sleuth kit) for $part"
  if fls -r -m / "$part" > "${dest}/bodyfile.txt" 2>"${dest}/fls.err"; then
    mactime -b "${dest}/bodyfile.txt" -d -y > "${dest}/timeline-mactime.csv" 2>/dev/null || true
  else
    log "  fls could not parse $fstype on $part (continuing with mounted-filesystem timeline)"
  fi

  local opts; opts=$(mount_opts "$fstype")
  [[ -n "$opts" ]] || { log "  unsupported filesystem $fstype, skipping mount"; return 0; }
  if ! mount -o "$opts" "$part" "$mnt"; then
    log "  mount failed for $part"; return 0
  fi
  MOUNTS+=("$mnt")

  log "  find-based timeline"
  find "$mnt" -xdev -printf '%T+,%A+,%C+,%m,%U,%G,%s,%p\n' 2>/dev/null \
    | sed "s#${mnt}##" | sort -r > "${dest}/timeline-find.csv" || true
  sed -i '1i mtime,atime,ctime,mode,uid,gid,size,path' "${dest}/timeline-find.csv"

  log "  ClamAV scan"
  clamscan --recursive --infected --no-summary --cross-fs=no \
    --max-filesize=200M --max-scansize=400M "$mnt" > "${dest}/clamav.txt" 2>"${dest}/clamav.err" || true
  sed -i "s#${mnt}##" "${dest}/clamav.txt"

  log "  YARA scan"
  if [[ -s "${WORK}/combined-rules.yar" ]]; then
    yara --recursive --no-warnings --fast-scan "${WORK}/combined-rules.yar" "$mnt" \
      > "${dest}/yara.txt" 2>"${dest}/yara.err" || true
    sed -i "s#${mnt}##" "${dest}/yara.txt"
  else
    : > "${dest}/yara.txt"
  fi

  log "  collecting artifacts"
  local art="${dest}/artifacts"
  mkdir -p "$art"
  for p in etc/passwd etc/group etc/shadow etc/sudoers etc/sudoers.d etc/crontab etc/cron.d etc/cron.hourly \
           etc/cron.daily etc/systemd/system etc/rc.local etc/ld.so.preload etc/hosts etc/resolv.conf \
           etc/ssh/sshd_config var/spool/cron var/log/auth.log var/log/secure var/log/syslog var/log/messages \
           var/log/cloud-init-output.log var/log/audit root/.bash_history root/.ssh; do
    if [[ -e "${mnt}/${p}" ]]; then
      mkdir -p "${art}/$(dirname "$p")"
      cp -a --no-dereference "${mnt}/${p}" "${art}/${p}" 2>/dev/null || true
    fi
  done
  for h in "${mnt}"/home/*; do
    [[ -d "$h" ]] || continue
    local u; u=$(basename "$h")
    mkdir -p "${art}/home/${u}"
    for f in .bash_history .zsh_history .ssh/authorized_keys .ssh/known_hosts; do
      [[ -e "${h}/${f}" ]] && { mkdir -p "${art}/home/${u}/$(dirname "$f")"; cp -a "${h}/${f}" "${art}/home/${u}/${f}" 2>/dev/null || true; }
    done
  done

  log "  persistence and suspicious file heuristics"
  {
    find "${mnt}/etc/cron.d" "${mnt}/etc/cron.hourly" "${mnt}/etc/cron.daily" "${mnt}/var/spool/cron" \
      -type f 2>/dev/null
    find "${mnt}/etc/systemd/system" -name '*.service' -newer "${mnt}/etc/hostname" -type f 2>/dev/null
    [[ -s "${mnt}/etc/ld.so.preload" ]] && echo "${mnt}/etc/ld.so.preload"
    [[ -s "${mnt}/etc/rc.local" ]] && echo "${mnt}/etc/rc.local"
    find "${mnt}/root/.ssh" "${mnt}"/home/*/.ssh -name authorized_keys -type f 2>/dev/null
  } | sed "s#${mnt}##" | sort -u > "${dest}/persistence.txt" || true

  {
    find "${mnt}/tmp" "${mnt}/var/tmp" "${mnt}/dev/shm" -xdev -type f 2>/dev/null
    find "$mnt" -xdev -type f -name '.*' -perm /111 2>/dev/null
    find "${mnt}/tmp" "${mnt}/var/tmp" -xdev -type d -name '.*' 2>/dev/null
  } | sed "s#${mnt}##" | sort -u > "${dest}/suspicious-files.txt" || true

  find "$mnt" -xdev -type f -perm -4000 2>/dev/null | sed "s#${mnt}##" | sort > "${dest}/suid-files.txt" || true
  find "${mnt}/etc" "${mnt}/usr/bin" "${mnt}/usr/sbin" "${mnt}/usr/local" "${mnt}/root" "${mnt}/home" "${mnt}/tmp" \
    -xdev -type f -mtime "-${RECENT_DAYS}" 2>/dev/null | sed "s#${mnt}##" | sort > "${dest}/recently-modified.txt" || true

  umount "$mnt" || log "  warning: could not unmount $mnt"
  return 0
}

IFS=',' read -r -a PAIRS <<< "$VOLUMES"
VOL_JSON="${WORK}/volumes.jsonl"
: > "$VOL_JSON"
for pair in "${PAIRS[@]}"; do
  AVOL="${pair%%:*}"; SVOL="${pair##*:}"
  [[ "$AVOL" =~ ^vol-[0-9a-f]+$ && "$SVOL" =~ ^vol-[0-9a-f]+$ ]] || { log "bad volume pair $pair"; exit 2; }
  log "Volume ${SVOL} (analysis copy ${AVOL})"
  DEV=$(find_device "$AVOL")
  blockdev --setro "$DEV"
  log "  device ${DEV}, size $(blockdev --getsize64 "$DEV") bytes; hashing raw device"
  SHA=$(sha256sum "$DEV" | cut -d' ' -f1)
  log "  sha256 ${SHA}"
  VDIR="${OUT}/${SVOL}"
  mkdir -p "$VDIR"
  lsblk -o NAME,SIZE,TYPE,FSTYPE,LABEL,UUID,PARTLABEL "$DEV" > "${VDIR}/partitions.txt" || true

  FS_COUNT=0
  while read -r NAME _TYPE FSTYPE; do
    [[ -n "${FSTYPE:-}" ]] || continue
    case "$FSTYPE" in swap|LVM2_member|linux_raid_member) continue ;; esac
    FS_COUNT=$((FS_COUNT + 1))
    log " filesystem ${NAME} (${FSTYPE})"
    analyse_filesystem "$NAME" "$FSTYPE" "${VDIR}/$(basename "$NAME")" "${MNT_ROOT}/${AVOL}/$(basename "$NAME")"
  done < <(lsblk -lnpo NAME,TYPE,FSTYPE "$DEV")

  printf '{"source_volume_id":"%s","analysis_volume_id":"%s","device":"%s","sha256":"%s","filesystems":%d}\n' \
    "$SVOL" "$AVOL" "$DEV" "$SHA" "$FS_COUNT" >> "$VOL_JSON"
done

log "Building summary and report"
python3 - "$OUT" "$CASE_ID" "$VOL_JSON" <<'PY'
import json, os, sys, datetime
out, case_id, vol_json = sys.argv[1], sys.argv[2], sys.argv[3]
def lines(path):
    try:
        with open(path, errors="replace") as fh:
            return [l.rstrip("\n") for l in fh if l.strip()]
    except FileNotFoundError:
        return []
volumes = [json.loads(l) for l in open(vol_json) if l.strip()]
totals = {"clamav_detections": 0, "yara_matches": 0, "persistence_items": 0, "suspicious_files": 0, "suid_files": 0}
details = []
for v in volumes:
    vdir = os.path.join(out, v["source_volume_id"])
    for fs in sorted(os.listdir(vdir)):
        d = os.path.join(vdir, fs)
        if not os.path.isdir(d):
            continue
        clam = [l for l in lines(os.path.join(d, "clamav.txt")) if l.endswith("FOUND")]
        yara = lines(os.path.join(d, "yara.txt"))
        pers = lines(os.path.join(d, "persistence.txt"))
        susp = lines(os.path.join(d, "suspicious-files.txt"))
        suid = lines(os.path.join(d, "suid-files.txt"))
        totals["clamav_detections"] += len(clam); totals["yara_matches"] += len(yara)
        totals["persistence_items"] += len(pers); totals["suspicious_files"] += len(susp)
        totals["suid_files"] += len(suid)
        details.append({"volume": v["source_volume_id"], "filesystem": fs, "clamav": clam, "yara": yara,
                        "persistence": pers, "suspicious": susp[:200]})
tool_versions = dict(l.split("=", 1) for l in lines(os.path.join(out, "tool-versions.txt")) if "=" in l)
summary = {"case_id": case_id, "generated_at": datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
           "volumes": volumes, "totals": totals, "tool_versions": tool_versions, "details": details}
json.dump(summary, open(os.path.join(out, "summary.json"), "w"), indent=2)

verdict = "SUSPICIOUS" if totals["clamav_detections"] or totals["yara_matches"] else "NO KNOWN MALWARE DETECTED"
r = [f"# Forensic triage report: {case_id}", "", f"Generated: {summary['generated_at']}  ", f"Verdict: **{verdict}**", "",
     "## Evidence", "", "| Source volume | Analysis copy | SHA-256 of raw image | Filesystems |", "|---|---|---|---|"]
for v in volumes:
    r.append(f"| {v['source_volume_id']} | {v['analysis_volume_id']} | `{v['sha256']}` | {v['filesystems']} |")
r += ["", "## Totals", "", "| Check | Count |", "|---|---|"] + [f"| {k.replace('_', ' ')} | {n} |" for k, n in totals.items()]
for d in details:
    r += ["", f"## {d['volume']} / {d['filesystem']}", ""]
    for title, key in (("ClamAV detections", "clamav"), ("YARA matches", "yara"), ("Persistence locations", "persistence"),
                       ("Suspicious files (first 200)", "suspicious")):
        r.append(f"### {title}")
        r += [f"    {x}" for x in d[key]] or ["None"]
        r.append("")
r += ["## Tool versions", ""] + [f"    {k}: {v}" for k, v in tool_versions.items()]
r += ["", "Full timelines, artifacts and raw tool output are in the same S3 prefix. Integrity hashes: manifest.sha256."]
open(os.path.join(out, "report.md"), "w").write("\n".join(r) + "\n")
print(json.dumps(totals))
PY

log "Packaging artifacts and hashing outputs"
( cd "$OUT" && find . -type d -name artifacts -prune -print0 | xargs -0 -r tar czf artifacts.tar.gz && find . -type d -name artifacts -prune -exec rm -rf {} + )
( cd "$OUT" && find . -type f ! -name manifest.sha256 ! -name scan.log -print0 | sort -z | xargs -0 sha256sum > manifest.sha256 )

log "Uploading results to s3://${BUCKET}/cases/${CASE_ID}/analysis/"
aws s3 cp "$OUT" "s3://${BUCKET}/cases/${CASE_ID}/analysis/" --recursive --region "$REGION" \
  --sse aws:kms --sse-kms-key-id "$KMS_KEY_ID" --only-show-errors

cleanup_mounts
rm -rf "$WORK" "$MNT_ROOT"
log "Case ${CASE_ID}: scan complete"
