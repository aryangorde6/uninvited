from uninvited.rules import MAX_BAN, CatchRule, Window, ban_seconds, identity, network, never_ban
from uninvited.sshlog import Event


def ev(kind, t, ip="203.0.113.9", port=1):
    return Event(kind, ip, port, float(t))


def test_five_failures_in_ten_minutes_is_one_catch():
    rule = CatchRule()
    results = [rule.feed("vm1", ev("failed", t)) for t in (0, 60, 120, 180, 240)]
    assert results == [False, False, False, False, True]
    assert rule.feed("vm1", ev("failed", 300)) is False        # counting starts afresh


def test_failures_spread_over_more_than_ten_minutes_are_not_a_catch():
    rule = CatchRule()
    assert not any(rule.feed("vm1", ev("failed", t)) for t in (0, 200, 400, 600, 800))


def test_counts_are_per_server():
    rule = CatchRule()
    for t in range(4):
        rule.feed("vm1", ev("failed", t))
    assert rule.feed("vm2", ev("failed", 5)) is False
    assert rule.feed("vm1", ev("failed", 6)) is True


def test_invalid_user_pair_counts_once_per_attempt():
    rule = CatchRule()
    # five connections, each "Invalid user" then "Failed password for invalid user": five attempts
    out = []
    for port in range(1, 6):
        out.append(rule.feed("vm1", ev("invalid_user", port, port=port)))
        out.append(rule.feed("vm1", ev("failed_invalid", port, port=port)))
    assert out.count(True) == 1 and out[-2] is True
    # one connection with three password tries on an unknown user is three attempts
    rule = CatchRule()
    seq = [ev("invalid_user", 0, port=9)] + [ev("failed_invalid", i, port=9) for i in (1, 2, 3)]
    assert [rule.feed("vm1", e) for e in seq] == [False, False, False, False]
    assert len(rule.fails[("vm1", "203.0.113.9")]) == 3


def test_activity_and_drops_are_not_failures():
    rule = CatchRule()
    assert not any(rule.feed("vm1", ev(k, t)) for t in range(10) for k in ("activity", "dropped"))


def test_ban_seconds_never_trusts_the_flag():
    assert ban_seconds(600) == 600 and ban_seconds("43200") == 43200
    assert ban_seconds("0") == ban_seconds("none") == ban_seconds(None) == 0
    assert ban_seconds(-5) == ban_seconds("-5") == ban_seconds("1e9") == ban_seconds(True) == 0
    assert ban_seconds(10**9) == MAX_BAN == 43200
    assert ban_seconds(1.5) == 0


def test_identity_is_keyed_and_stable():
    a = identity("203.0.113.9", b"k1")
    assert a == identity("203.0.113.9", b"k1") and a.startswith("ip-") and len(a) == 23
    assert a != identity("203.0.113.9", b"k2") and a != identity("203.0.113.8", b"k1")


def test_never_ban():
    assert never_ban("10.0.0.5", set()) and never_ban("127.0.0.1", set()) and never_ban("192.168.1.1", set())
    assert never_ban("100.64.0.1", set()) and never_ban("224.0.0.1", set())
    assert never_ban("8.8.8.8", {"8.8.8.8"}) and not never_ban("8.8.8.8", set())


def test_window_opens_after_the_longest_ban():
    w = Window()
    assert not w.contains(0, 12 * 3600 + 299) and w.contains(0, 12 * 3600 + 300)
    assert w.contains(0, 24 * 3600 + 299) and not w.contains(0, 24 * 3600 + 300)


def test_network_hash_groups_a_slash_24_and_hides_it():
    key = b"k" * 32
    same = network("81.2.69.142", key) == network("81.2.69.7", key)
    other = network("81.2.70.142", key)
    assert same and other != network("81.2.69.142", key)
    assert network("81.2.69.142", key).startswith("net-")
    assert network("81.2.69.142", key) != network("81.2.69.142", b"j" * 32)
    assert network("81.2.69.142", key)[4:] not in identity("81.2.69.0", key)
