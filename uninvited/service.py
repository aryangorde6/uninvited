"""The ban service's brain. It sees every event from every server and decides:
enrol, ban, or report `came_back`. Flagsmith, the bans and the log are passed in,
so the same code runs live, in the tests and in the answer-key test.
"""
import fcntl
import json
import os
from dataclasses import asdict, dataclass

from .rules import CatchRule, Window, ban_seconds, identity, network, never_ban


@dataclass
class Attacker:
    arm: str              # the flag value Flagsmith gave, as text ("0", "600", "43200", "none")
    seconds: int          # the ban length that value means, after the cap
    first_catch: float
    first_vm: str
    came_back_at: float = 0.0
    net: str = ""         # keyed hash of the /24 (see rules.network)
    asn: int = 0          # network operator at enrolment (0 = unknown); no address is kept
    country: str = ""


class State:
    """Enrolled attackers by identity, saved as JSON after every change. No raw IPs."""

    def __init__(self, path):
        self.path = path
        self.attackers = {}
        if os.path.exists(path):
            with open(path) as f:
                self.attackers = {k: Attacker(**v) for k, v in json.load(f).items()}

    def save(self):
        tmp = self.path + ".tmp"
        with open(tmp, "w") as f:
            json.dump({k: asdict(v) for k, v in self.attackers.items()}, f)
        os.replace(tmp, self.path)


def single_instance(lock_path):
    """Hold an exclusive lock for the life of the process, so two controllers never run at once."""
    handle = open(lock_path, "w")
    try:
        fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        raise SystemExit(f"another controller holds {lock_path}")
    return handle


class Service:
    def __init__(self, *, state, flags, ban, log, hash_key, protected,
                 enrol_from, enrol_until, max_enrolled=5000, window=None, catch_rule=None, asn=None):
        self.state, self.flags, self.ban, self.log = state, flags, ban, log
        self.hash_key, self.protected = hash_key, set(protected)
        self.enrol_from, self.enrol_until, self.max_enrolled = enrol_from, enrol_until, max_enrolled
        self.window = window or Window()
        self.asn = asn or (lambda ip: (0, ""))
        self.catches = catch_rule or CatchRule()

    def handle(self, vm, ev):
        ident = identity(ev.ip, self.hash_key)
        who = self.state.attackers.get(ident)

        if who is not None:
            self.log({"t": ev.ts, "what": ev.kind, "vm": vm, "id": ident})
            if not who.came_back_at and self.window.contains(who.first_catch, ev.ts):
                who.came_back_at = ev.ts
                self.state.save()
                self.flags.came_back(ident)
                self.log({"t": ev.ts, "what": "came_back", "vm": vm, "id": ident, "arm": who.arm,
                          "hours": round((ev.ts - who.first_catch) / 3600, 3)})

        if not self.catches.feed(vm, ev):
            return
        if never_ban(ev.ip, self.protected):
            self.log({"t": ev.ts, "what": "catch_protected", "vm": vm})
            return
        enforcing = self.flags.enforcing()

        if who is None:
            reason = self.why_not_enrol(ev.ts, enforcing)
            if reason:
                self.log({"t": ev.ts, "what": "catch_not_enrolled", "vm": vm, "id": ident, "why": reason})
                return
            try:
                value = self.flags.assign(ident)      # the one Flagsmith evaluation for this identity
            except Exception as e:                    # Flagsmith unreachable: observe only, retry at the next catch
                self.log({"t": ev.ts, "what": "catch_flagsmith_error", "vm": vm, "id": ident,
                          "error": type(e).__name__})
                return
            if value is None:
                self.log({"t": ev.ts, "what": "catch_not_in_experiment", "vm": vm, "id": ident})
                return
            try:
                asn, country = self.asn(ev.ip)
            except Exception:                         # never let the lookup stop an enrolment
                asn, country = 0, ""
            who = Attacker(arm=str(value), seconds=ban_seconds(value), first_catch=ev.ts, first_vm=vm,
                           net=network(ev.ip, self.hash_key), asn=asn, country=country)
            self.state.attackers[ident] = who
            self.state.save()
            self.log({"t": ev.ts, "what": "enrolled", "vm": vm, "id": ident, "arm": who.arm, "net": who.net,
                      "asn": who.asn, "country": who.country})

        if who.seconds > 0 and enforcing:
            self.ban(ev.ip, who.seconds, ev.ts)
            self.log({"t": ev.ts, "what": "banned", "vm": vm, "id": ident, "arm": who.arm, "seconds": who.seconds})
        else:
            self.log({"t": ev.ts, "what": "caught_not_banned", "vm": vm, "id": ident, "arm": who.arm,
                      "why": "arm has no ban" if enforcing else "ban_enforce is off"})

    def why_not_enrol(self, ts, enforcing):
        if not enforcing:
            return "ban_enforce is off"
        if not self.enrol_from <= ts < self.enrol_until:
            return "outside the enrolment window"
        if len(self.state.attackers) >= self.max_enrolled:
            return "enrolment cap reached"
        return None
