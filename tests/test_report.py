import random

from uninvited.report import beta_compare, report, srm_p

H = 3600
NOW = 100 * H


def fake(rates, n=300, seed=1):
    """Attackers with known return rates per arm: an answer key for the analysis."""
    rng, out, i = random.Random(seed), {}, 0
    for value, rate in rates.items():
        for _ in range(n):
            back = rng.random() < rate
            out[f"ip-{i:020x}"] = {"arm": value, "seconds": int(value), "first_catch": 0.0, "first_vm": "vm1",
                                    "came_back_at": 13.0 * H if back else 0.0,
                                    "net": f"net-{i:012x}", "asn": 1000 + i, "country": "US"}
            i += 1
    return out


def came_back_log(attackers):
    return [{"what": "came_back", "id": k} for k, a in attackers.items() if a["came_back_at"]]


def flagsmith_numbers(attackers):
    names = {"0": "control", "600": "ban_10m", "43200": "ban_12h"}
    fs = {v: {"exposures": 0, "conversions": 0} for v in names.values()}
    for a in attackers.values():
        fs[names[a["arm"]]]["exposures"] += 1
        fs[names[a["arm"]]]["conversions"] += bool(a["came_back_at"])
    return fs


def test_planted_winner_is_found_and_a_tie_is_not_called():
    att = fake({"0": 0.40, "600": 0.40, "43200": 0.10})
    text, ok = report(att, came_back_log(att), NOW, flagsmith_numbers(att))
    assert ok, text
    lines = text.splitlines()
    first = next(i for i, l in enumerate(lines) if l.startswith("Primary"))
    block = "\n".join(lines[first:first + 8])
    assert "ban_12h vs control" in block and ": lower" in block
    assert "ban_10m vs control" in block and "can't call it" in block


def test_planted_fault_fails_the_gate():
    att = fake({"0": 0.3, "600": 0.3, "43200": 0.3})
    fs = flagsmith_numbers(att)
    fs["ban_10m"]["conversions"] = 0                  # e.g. the event name sent in the wrong case
    text, ok = report(att, came_back_log(att), NOW, fs)
    assert not ok and "[FAIL] Flagsmith conversions = came_back (ban_10m)" in text


def test_open_windows_are_left_out_of_rates():
    att = fake({"0": 0.5, "600": 0.5, "43200": 0.5}, n=10)
    for a in att.values():
        a["first_catch"] = NOW - 2 * H                 # window still open
    text, _ = report(att, came_back_log(att), NOW)
    assert "window has closed: 0 of 30" in text


def test_sample_ratio_and_beta():
    assert srm_p({"control": 340, "ban_10m": 330, "ban_12h": 330}) > 0.9
    assert srm_p({"control": 500, "ban_10m": 250, "ban_12h": 250}) < 0.001
    p_lower, lo, hi = beta_compare(1000, 400, 1000, 100)
    assert p_lower > 0.999 and hi < 0
