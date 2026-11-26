#!/usr/bin/env bash
# Put the committed controller code on the controller and restart it, with checks.
#
#   UNINVITED_ADMIN_PORT=<port> fleet/update-controller.sh <controller host>        # compare only
#   UNINVITED_ADMIN_PORT=<port> fleet/update-controller.sh <controller host> --go   # install and restart
#
# Without --go it only reads: which files differ from HEAD, and the unit's stop settings.
# With --go it backs up the controller's data to data/backup/, installs uninvited/*.py and the
# systemd unit exactly as committed at HEAD, restarts the service, waits a minute and reports
# what the controller logged: a clean stop (buffered events sent), the start, every log stream,
# the kill switch and `ban_policy`'s value for everyone.
set -euo pipefail
cd "$(dirname "$0")/.."
HOST=${1:?usage: update-controller.sh <controller host> [--go]}
GO=${2:-}
PORT=${UNINVITED_ADMIN_PORT:?set UNINVITED_ADMIN_PORT}
KEY=${UNINVITED_ADMIN_KEY:-$HOME/.ssh/uninvited_admin}
KNOWN=${UNINVITED_KNOWN_HOSTS:-data/known_hosts}
rsh() {
  ssh -i "$KEY" -o IdentitiesOnly=yes -o BatchMode=yes -o ConnectTimeout=10 -o UserKnownHostsFile="$KNOWN" \
      -o StrictHostKeyChecking=yes -p "$PORT" "ubuntu@$HOST" "$@"
}

git diff --quiet HEAD -- uninvited fleet/uninvited-controller.service \
  || { echo "uncommitted changes in uninvited/ or the unit: commit first, so the controller runs a known commit"; exit 1; }
REV=$(git rev-parse --short HEAD)
mapfile -t FILES < <(git ls-files 'uninvited/*.py' fleet/uninvited-controller.service)

remote=$(rsh "cd /opt/uninvited && sha256sum ${FILES[*]} 2>/dev/null || true")
changed=0
for f in "${FILES[@]}"; do
  here=$(git show "HEAD:$f" | sha256sum | cut -d' ' -f1)
  there=$(awk -v f="$f" '$2 == f {print $1}' <<<"$remote")
  if [ "$here" != "$there" ]; then echo "differs from $REV: $f"; changed=1; fi
done
echo "running: $(rsh 'systemctl show uninvited-controller -p ActiveState -p NRestarts -p KillSignal -p ActiveEnterTimestamp' | tr '\n' ' ')"
[ "$changed" = 1 ] || { echo "the controller already runs $REV"; exit 0; }
[ "$GO" = "--go" ] || { echo "compare only: nothing changed. Add --go to install $REV and restart."; exit 0; }

T=$(date +%Y%m%d-%H%M)
mkdir -p data/backup
rsh 'sudo tar -C /var/lib -czf - uninvited' > "data/backup/controller-$T.tgz"
tar -tzf "data/backup/controller-$T.tgz" uninvited/state.json uninvited/events.jsonl >/dev/null
echo "backup: data/backup/controller-$T.tgz"
before=$(rsh 'sudo wc -l < /var/lib/uninvited/events.jsonl')

git archive HEAD "${FILES[@]}" | rsh 'set -e
  D=$(mktemp -d); tar -C "$D" -x
  sudo install -m 0644 -o root -g root "$D"/uninvited/*.py /opt/uninvited/uninvited/
  sudo install -m 0644 -o root -g root "$D"/fleet/uninvited-controller.service /opt/uninvited/fleet/
  sudo install -m 0644 -o root -g root "$D"/fleet/uninvited-controller.service /etc/systemd/system/
  rm -rf "$D"
  sudo systemctl daemon-reload
  echo "unit after reload: $(systemctl show uninvited-controller -p KillSignal)"'
echo "installed $REV; restarting at $(date '+%-I:%M:%S %p')"
rsh 'sudo systemctl restart uninvited-controller'
sleep 60

rsh "sudo tail -n +$((before + 1)) /var/lib/uninvited/events.jsonl" | python3 -c '
import collections, json, sys
ev = [json.loads(line) for line in sys.stdin if line.strip()]
seen = collections.Counter(e["what"] for e in ev)
def last(what, key):
    vals = [e.get(key) for e in ev if e["what"] == what]
    return vals[-1] if vals else "(not logged)"
print("clean stop (buffered events sent):", "yes" if seen["controller_stop"] else "NO")
print("started:", seen["controller_start"], "time(s); log streams up:", seen["stream_up"])
print("kill switch enforcing:", last("kill_switch", "enforcing"))
print("ban_policy for everyone:", last("rollout_policy", "value"))
print("event batches since the restart:", [e.get("status") for e in ev if e["what"] == "events_post"])
starts = [i for i, e in enumerate(ev) if e["what"] == "controller_start"]
after = collections.Counter(e["what"] for e in ev[starts[-1]:]) if starts else seen   # links drop during the stop
bad = {w: n for w, n in after.items() if w.endswith(("_unreadable", "_error", "_down"))}
print("problems:", bad or "none")'
rsh 'systemctl show uninvited-controller -p ActiveState -p NRestarts -p ActiveEnterTimestamp' | tr '\n' ' '; echo
