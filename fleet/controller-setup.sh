#!/bin/sh
# Run once on the controller, as root, from the folder the code was copied to (/opt/uninvited).
# Makes the service user, the two limited SSH keys and the hashing key here, so no private
# key ever leaves this machine. Prints only the two public keys.
set -eu
cloud-init status --wait >/dev/null || true
id uninvited >/dev/null 2>&1 || useradd --system --home-dir /var/lib/uninvited --shell /usr/sbin/nologin uninvited
install -d -m 0750 -o root -g uninvited /etc/uninvited /etc/uninvited/ssh
install -d -m 0700 -o uninvited -g uninvited /var/lib/uninvited
for k in log ban; do
  [ -f /etc/uninvited/ssh/$k ] || ssh-keygen -q -t ed25519 -N '' -C "uninvited-$k" -f /etc/uninvited/ssh/$k
done
[ -f /etc/uninvited/hash.key ] || head -c 32 /dev/urandom > /etc/uninvited/hash.key
chown root:uninvited /etc/uninvited/ssh/log /etc/uninvited/ssh/ban /etc/uninvited/hash.key
chmod 0640 /etc/uninvited/ssh/log /etc/uninvited/ssh/ban /etc/uninvited/hash.key
touch /etc/uninvited/ssh/known_hosts && chown root:uninvited /etc/uninvited/ssh/known_hosts && chmod 0640 /etc/uninvited/ssh/known_hosts
[ -d /opt/uninvited/.venv ] || python3 -m venv /opt/uninvited/.venv
/opt/uninvited/.venv/bin/pip install --quiet --disable-pip-version-check flagsmith==6.7.0
install -m 0644 /opt/uninvited/fleet/uninvited-controller.service /etc/systemd/system/uninvited-controller.service
systemctl daemon-reload
cat /etc/uninvited/ssh/log.pub /etc/uninvited/ssh/ban.pub
