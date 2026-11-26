"""The public, anonymised dataset: what the website, the replay and the README read.

  python -m uninvited.export --data /var/lib/uninvited --out snapshot.json

It reads the controller's own files (state.json, events.jsonl) and keeps only what is safe
to publish: the keyed hash that stands for each attacker (no address can be recovered from
it without the controller's secret key), its arm, times, the server that first caught it,
the network operator's number and country, and counts. No address, username or password is
in the controller's files to begin with; a final check refuses to write anything that looks
like an IPv4 address anyway.
"""
import argparse
import json
import re
import time
from datetime import datetime

from .report import ARMS, WINDOW_END, closed, load, report

WINDOW_START = 12 * 3600 + 300                     # returns count from 12h05m after the first catch...
ENROL_FROM = "2026-11-26T14:00:00+05:30"           # ...to 24h05m (WINDOW_END); dates as pre-registered
ENROL_UNTIL = "2026-11-27T15:00:00+05:30"
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")


def per_attacker_counts(events):
    """Events after enrolment, per attacker: attempts that reached SSH, packets dropped by a ban, bans."""
    counts = {}
    for e in events:
        ident = e.get("id")
        if not ident:
            continue
        c = counts.setdefault(ident, {"attempts": 0, "dropped": 0, "bans": 0})
        what = e.get("what")
        if what == "dropped":
            c["dropped"] += 1
        elif what == "banned":
            c["bans"] += 1
        elif what in ("failed", "failed_invalid", "invalid_user", "activity"):
            c["attempts"] += 1
    return counts


def servers(events, since):
    """Events seen per server (all clients, enrolled or not), from the controller's 5-minute heartbeats."""
    out, last = {}, 0.0
    for e in events:
        if e.get("what") == "health" and e.get("t", 0) >= since:
            last = max(last, e["t"])
            for name, n in e.get("events_5min", {}).items():
                out[name] = out.get(name, 0) + n
    rows = [{"name": name, "region": name.split("-", 1)[1].rsplit("-", 1)[0] if name.count("-") >= 2 else "",
             "events": n} for name, n in sorted(out.items())]
    return rows, last


def snapshot(attackers, events, now):
    since = datetime.fromisoformat(ENROL_FROM).timestamp()
    counts = per_attacker_counts(events)
    rows = []
    for ident, a in sorted(attackers.items(), key=lambda kv: kv[1]["first_catch"]):
        c = counts.get(ident, {"attempts": 0, "dropped": 0, "bans": 0})
        back = a.get("came_back_at") or 0.0
        rows.append({
            "id": ident,
            "arm": ARMS.get(str(a["arm"]), "other"),
            "ban_seconds": a.get("seconds", 0),
            "first_catch": round(a["first_catch"], 1),
            "first_server": a.get("first_vm", ""),
            "asn": a.get("asn", 0),
            "country": a.get("country", ""),
            "net": a.get("net", ""),
            "came_back_hours": round((back - a["first_catch"]) / 3600, 2) if back else None,
            "window": "closed" if a["first_catch"] + WINDOW_END <= now else
                      ("open" if a["first_catch"] + WINDOW_START <= now else "not started"),
            **c,
        })
    batches = [e.get("status", "") for e in events if e.get("what") == "events_post"]
    replies = [e.get("reply", "") for e in events if e.get("what") == "ban_reply"]
    server_rows, last_health = servers(events, since)
    gate_text, gate_ok = report(attackers, events, now)
    done = closed(attackers, now)
    per_arm = {arm: {"enrolled": 0, "closed": 0, "came_back": 0} for arm in ("control", "ban_10m", "ban_12h")}
    for ident, a in attackers.items():
        arm = ARMS.get(str(a["arm"]))
        if arm in per_arm:
            per_arm[arm]["enrolled"] += 1
            if ident in done:
                per_arm[arm]["closed"] += 1
                per_arm[arm]["came_back"] += bool(a.get("came_back_at"))
    return {
        "generated": round(now, 1),
        "experiment": {"enrol_from": ENROL_FROM, "enrol_until": ENROL_UNTIL,
                       "window_hours": [WINDOW_START / 3600, WINDOW_END / 3600],
                       "arms": {"control": 0, "ban_10m": 600, "ban_12h": 43200}, "split": [34, 33, 33]},
        "totals": {"enrolled": len(attackers), "per_arm": per_arm,
                   "ban_replies_ok": replies.count("ok"), "ban_replies_other": len(replies) - replies.count("ok"),
                   "event_batches": len(batches), "event_batches_not_2xx": sum(not s.startswith("2") for s in batches),
                   "dropped": sum(r["dropped"] for r in rows)},
        "gate": {"pass": gate_ok, "text": gate_text},
        "servers": server_rows,
        "last_heartbeat": round(last_health, 1),
        "attackers": rows,
    }


def dumps_checked(data):
    text = json.dumps(data, indent=1, sort_keys=True)
    found = IPV4.findall(text)
    if found:
        raise SystemExit(f"REFUSED: {len(found)} address-like strings in the output; nothing written")
    return text


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--out", default="snapshot.json")
    ap.add_argument("--now", type=float, default=None)
    a = ap.parse_args()
    attackers, events = load(a.data)
    text = dumps_checked(snapshot(attackers, events, a.now or time.time()))
    with open(a.out, "w") as f:
        f.write(text + "\n")
    print(f"{len(attackers)} attackers written to {a.out}")


if __name__ == "__main__":
    main()
