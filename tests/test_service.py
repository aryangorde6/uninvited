from uninvited.rules import identity, network
from uninvited.service import Service, State
from uninvited.sshlog import Event

KEY = b"test-key"
H = 3600


class FakeFlags:
    def __init__(self, arms, enforce=True):
        self.arms, self.enforce, self.assigned, self.events = arms, enforce, [], []

    def assign(self, ident):
        self.assigned.append(ident)
        return self.arms.get(ident)

    def came_back(self, ident):
        self.events.append(ident)

    def enforcing(self):
        return self.enforce


def make(tmp_path, arms, enforce=True, **kw):
    flags, bans, log = FakeFlags(arms, enforce), [], []
    svc = Service(state=State(str(tmp_path / "state.json")), flags=flags,
                  ban=lambda ip, s, t: bans.append((ip, s)), log=log.append,
                  hash_key=KEY, protected={"198.51.100.1"}, enrol_from=0, enrol_until=48 * H, **kw)
    return svc, flags, bans, log


def attack(svc, ip, t0, vm="vm1", n=5):
    for i in range(n):
        svc.handle(vm, Event("failed", ip, 1000 + i, t0 + i))


IP = "81.2.69.142"   # a public address (203.0.113.x is a documentation range, which is never banned)
ID = identity(IP, KEY)


def test_catch_enrols_once_and_bans_for_the_arm(tmp_path):
    svc, flags, bans, _ = make(tmp_path, {ID: 600})
    attack(svc, IP, 0)
    assert flags.assigned == [ID] and bans == [(IP, 600)]
    attack(svc, IP, 1000, vm="vm2")                      # caught again later: same arm, no second evaluation
    assert flags.assigned == [ID] and bans == [(IP, 600), (IP, 600)]
    assert svc.state.attackers[ID].first_vm == "vm1"
    assert svc.state.attackers[ID].net == network(IP, KEY)
    assert State(str(tmp_path / "state.json")).attackers[ID].net == network(IP, KEY)   # survives a restart


def test_no_ban_arm_and_cap(tmp_path):
    svc, _, bans, log = make(tmp_path, {ID: "none"})
    attack(svc, IP, 0)
    assert bans == [] and log[-1]["what"] == "caught_not_banned"
    svc, _, bans, _ = make(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path, {ID: 10**9})
    attack(svc, IP, 0)
    assert bans == [(IP, 43200)]


def test_came_back_only_inside_the_window_and_only_once(tmp_path):
    svc, flags, _, _ = make(tmp_path, {ID: 43200})
    attack(svc, IP, 0)
    svc.handle("vm3", Event("activity", IP, 5, 12 * H))           # before 12h05m: not yet
    assert flags.events == []
    svc.handle("vm3", Event("dropped", IP, 0, 12 * H + 400))       # a dropped packet counts as a return
    svc.handle("vm1", Event("failed", IP, 6, 13 * H))
    assert flags.events == [ID]
    assert State(str(tmp_path / "state.json")).attackers[ID].came_back_at == 12 * H + 400


def test_returns_after_the_window_do_not_count(tmp_path):
    svc, flags, _, _ = make(tmp_path, {ID: 0})
    attack(svc, IP, 0)
    svc.handle("vm1", Event("activity", IP, 5, 24 * H + 304))   # first catch was at t=4, so this is 24h05m after it
    assert flags.events == []


def test_kill_switch_stops_enrolment_and_bans(tmp_path):
    svc, flags, bans, log = make(tmp_path, {ID: 600}, enforce=False)
    attack(svc, IP, 0)
    assert flags.assigned == [] and bans == [] and log[-1]["why"] == "ban_enforce is off"
    flags.enforce = True
    attack(svc, IP, 100)
    assert bans == [(IP, 600)]
    flags.enforce = False
    attack(svc, IP, 200)                                   # enrolled, but no new bans while off
    assert bans == [(IP, 600)] and log[-1]["what"] == "caught_not_banned"


def test_protected_and_private_addresses_are_never_enrolled_or_banned(tmp_path):
    svc, flags, bans, _ = make(tmp_path, {})
    attack(svc, "198.51.100.1", 0)
    attack(svc, "10.1.2.3", 0)
    assert flags.assigned == [] and bans == []


def test_enrolment_window_and_cap(tmp_path):
    svc, flags, bans, log = make(tmp_path, {ID: 600})
    attack(svc, IP, 48 * H)
    assert flags.assigned == [] and log[-1]["why"] == "outside the enrolment window"
    other = "81.2.69.143"
    svc2, flags2, _, log2 = make(tmp_path / "c" if (tmp_path / "c").mkdir() is None else tmp_path,
                                 {ID: 600, identity(other, KEY): 0}, max_enrolled=1)
    attack(svc2, IP, 0)
    attack(svc2, other, 0)
    assert len(flags2.assigned) == 1 and log2[-1]["why"] == "enrolment cap reached"


def test_identity_outside_the_experiment_is_not_recorded(tmp_path):
    svc, flags, bans, log = make(tmp_path, {})
    attack(svc, IP, 0)
    assert flags.assigned == [ID] and bans == [] and svc.state.attackers == {}
    assert log[-1]["what"] == "catch_not_in_experiment"


def test_state_survives_a_restart(tmp_path):
    svc, _, _, _ = make(tmp_path, {ID: 600})
    attack(svc, IP, 0)
    svc2, flags2, bans2, _ = make(tmp_path, {ID: 43200})   # a new process; Flagsmith must not be asked again
    attack(svc2, IP, 100)
    assert flags2.assigned == [] and bans2 == [(IP, 600)]


def test_log_has_no_raw_ip(tmp_path):
    svc, _, _, log = make(tmp_path, {ID: 600})
    attack(svc, IP, 0)
    svc.handle("vm1", Event("activity", IP, 1, 13 * H))
    assert log and all(IP not in str(line) for line in log)
    assert IP not in (tmp_path / "state.json").read_text()


def test_flagsmith_error_means_observe_only_and_retry(tmp_path):
    svc, flags, bans, log = make(tmp_path, {ID: 600})
    real = flags.assign
    flags.assign = lambda ident: (_ for _ in ()).throw(ConnectionError("down"))
    attack(svc, IP, 0)
    assert bans == [] and log[-1]["what"] == "catch_flagsmith_error" and svc.state.attackers == {}
    flags.assign = real
    attack(svc, IP, 100)
    assert bans == [(IP, 600)]
