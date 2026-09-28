#!/bin/bash
# First-boot bootstrap for the forensic workstation (Ubuntu 24.04 LTS).
# Installs open-source DFIR tooling. Access is only through AWS Systems Manager;
# there is no SSH key and no inbound security group rule.
set -euxo pipefail
export DEBIAN_FRONTEND=noninteractive

# Never auto-mount or auto-repair attached evidence volumes.
systemctl mask udisks2.service 2>/dev/null || true

# Ubuntu runs unattended-upgrades on first boot; wait for the dpkg lock instead of failing.
APT="apt-get -o DPkg::Lock::Timeout=900"
$APT update -y
$APT install -y --no-install-recommends \
  sleuthkit clamav clamav-freshclam yara jq unzip python3 xfsprogs e2fsprogs ntfs-3g dosfstools \
  lvm2 file binutils

# Keep LVM from auto-activating volume groups found on evidence disks.
sed -i 's/^\(\s*\)# *event_activation = 1/\1event_activation = 0/' /etc/lvm/lvm.conf || true

# ClamAV signatures
systemctl stop clamav-freshclam || true
freshclam || true
systemctl enable --now clamav-freshclam || true

# AWS CLI v2 (Ubuntu AMIs ship snapd and the SSM agent snap)
if ! command -v aws >/dev/null 2>&1; then
  snap install aws-cli --classic
fi

mkdir -p /opt/forensics/rules /forensics/cases /mnt/evidence
chmod 700 /forensics /mnt/evidence

# Unattended security updates for the workstation OS
$APT install -y unattended-upgrades
touch /opt/forensics/.bootstrap-complete
