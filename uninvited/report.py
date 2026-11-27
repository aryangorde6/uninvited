"""The integrity gate and the pre-registered analysis, from the controller's own files.

  python -m uninvited.report --data /var/lib/uninvited                      # gate checks + results
  python -m uninvited.report --data DIR --flagsmith flagsmith.json          # also compare with Flagsmith
  python -m uninvited.report --snapshot site/data/snapshot.json             # the same, from the published dataset

flagsmith.json holds the numbers read off Flagsmith's results page, per arm:
  {"control": {"exposures": 120, "conversions": 18}, "ban_10m": {...}, "ban_12h": {...}}

Standard library only, so a judge can run it on the published dataset with nothing installed.
"""
import argparse
import json
import math
import os
import random
import time

ARMS = {"0": "control", "600": "ban_10m", "43200": "ban_12h"}     # flag value -> variation name
WEIGHTS = {"control": 34, "ban_10m": 33, "ban_12h": 33}            # the experiment's split, in %
WINDOW_END = 24 * 3600 + 300                                         # a window closes 24h05m after the first catch


def load(data_dir):
    attackers = {}
    path = os.path.join(data_dir, "state.json")
    if os.path.exists(path):                     # no file until the first enrolment
        with open(path) as f:
            attackers = json.load(f)
    events = []
    path = os.path.join(data_dir, "events.jsonl")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                try:
                    events.append(json.loads(line))
                except ValueError:
                    pass
    return attackers, events


def load_snapshot(path):
    """The published, anonymised dataset (site/data/snapshot.json) turned back into the controller's
    state format, so the same analysis runs on it. Returns (attackers, totals, generated)."""
    with open(path) as f:
        snap = json.load(f)
    values = {name: value for value, name in ARMS.items()}
    attackers = {}
    for r in snap["attackers"]:
        hours = r.get("came_back_hours")
        attackers[r["id"]] = {"arm": values.get(r["arm"], r["arm"]), "seconds": r.get("ban_seconds", 0),
                              "first_catch": r["first_catch"], "first_vm": r.get("first_server", ""),
                              "came_back_at": r["first_catch"] + hours * 3600 if hours is not None else 0.0,
                              "net": r.get("net", ""), "asn": r.get("asn", 0), "country": r.get("country", "")}
    return attackers, snap.get("totals", {}), snap.get("generated")


def arm_of(a):
    return ARMS.get(str(a["arm"]), "other")


def closed(attackers, now):
    """Only attackers whose 12h05m-24h05m window has ended count in a return rate."""
    return {k: a for k, a in attackers.items() if a["first_catch"] + WINDOW_END <= now}


def rates(attackers):
    out = {arm: [0, 0] for arm in WEIGHTS}
    for a in attackers.values():
        arm = arm_of(a)
        if arm in out:
            out[arm][0] += 1
            out[arm][1] += 1 if a.get("came_back_at") else 0
    return out      # arm -> [n, came_back]


def srm_p(counts):
    """Sample-ratio test: chi-square with 2 degrees of freedom, whose p-value is exp(-x/2)."""
    total = sum(counts.values())
    if not total:
        return 1.0
    x = sum((counts[a] - total * w / 100) ** 2 / (total * w / 100) for a, w in WEIGHTS.items())
    return math.exp(-x / 2)


def two_prop_p(n1, k1, n2, k2):
    """Two-sided p-value for a difference in two proportions (pooled z-test)."""
    if not n1 or not n2:
        return 1.0
    p = (k1 + k2) / (n1 + n2)
    se = math.sqrt(p * (1 - p) * (1 / n1 + 1 / n2))
    if se == 0:
        return 1.0
    return math.erfc(abs(k1 / n1 - k2 / n2) / se / math.sqrt(2))


def beta_compare(n_a, k_a, n_b, k_b, draws=100_000, seed=26):
    """Beta(1+k, 1+n-k) posteriors. Returns P(rate_b < rate_a) and the 95% interval of rate_b - rate_a."""
    rng = random.Random(seed)
    diffs = sorted(rng.betavariate(1 + k_b, 1 + n_b - k_b) - rng.betavariate(1 + k_a, 1 + n_a - k_a)
                   for _ in range(draws))
    lower = sum(d < 0 for d in diffs) / draws
    return lower, diffs[int(0.025 * draws)], diffs[int(0.975 * draws) - 1]


def one_per(attackers, field):
    """One unit per cluster (the earliest-caught attacker in each /24 or each ASN)."""
    best = {}
    for k, a in attackers.items():
        c = a.get(field)
        if not c:
            continue
        if c not in best or a["first_catch"] < best[c][1]["first_catch"]:
            best[c] = (k, a)
    return dict(best.values())


def mde(n, base):
    """Smallest absolute drop detectable with 80% power at the 5% level (two-sided), n per arm."""
    if not n or not 0 < base < 1:
        return None
    return (1.96 + 0.84) * math.sqrt(2 * base * (1 - base) / n)


def comparison(label, attackers, out):
    r = rates(attackers)
    out.append(f"\n{label}")
    for arm, (n, k) in r.items():
        out.append(f"  {arm:8} {k:5} of {n:5} came back" + (f"  ({100 * k / n:.1f}%)" if n else ""))
    (n0, k0) = r["control"]
    for arm in ("ban_10m", "ban_12h"):
        n1, k1 = r[arm]
        if n0 and n1:
            p_lower, lo, hi = beta_compare(n0, k0, n1, k1)
            verdict = "can't call it (interval spans zero)" if lo < 0 < hi else ("lower" if hi < 0 else "higher")
            out.append(f"  {arm} vs control: P(lower) = {100 * p_lower:.1f}%, difference "
                       f"{100 * (k1 / n1 - k0 / n0):+.1f} points, 95% interval {100 * lo:+.1f} to {100 * hi:+.1f}: {verdict}")
    if n0:
        d = mde(min(n for n, _ in r.values()) or n0, k0 / n0 if k0 else 0.15)
        if d:
            out.append(f"  smallest drop this sample could detect: about {100 * d:.0f} points")
    return r


def report(attackers, events, now, flagsmith=None, published=None):
    """`published`: the snapshot's totals, when reading the published dataset (which has no event log)."""
    out, ok = [], True

    def check(name, passed, detail):
        nonlocal ok
        ok = ok and passed
        out.append(f"  [{'PASS' if passed else 'FAIL'}] {name}: {detail}")

    enrolled = {arm: 0 for arm in WEIGHTS}
    for a in attackers.values():
        if arm_of(a) in enrolled:
            enrolled[arm_of(a)] += 1
    others = sum(arm_of(a) == "other" for a in attackers.values())
    out.append("INTEGRITY GATE")
    p = srm_p(enrolled)
    check("sample ratio (34/33/33)", p > 0.01, f"{enrolled}, p = {p:.3f}")
    check("no unknown arm values", others == 0, f"{others} attackers with a value outside 0/600/43200")

    if published is None:
        logged = {e["id"] for e in events if e.get("what") == "came_back"}
        in_state = {k for k, a in attackers.items() if a.get("came_back_at")}
        check("came_back: log matches state", logged == in_state, f"{len(logged)} logged, {len(in_state)} in state")
        posts = [e.get("status", "") for e in events if e.get("what") == "events_post"]
        n_posts, n_bad = len(posts), sum(not s.startswith("2") for s in posts)
    else:
        out.append("  [----] came_back log against state skipped (the controller's event log isn't published)")
        n_posts, n_bad = published.get("event_batches", 0), published.get("event_batches_not_2xx", 0)
    check("every event batch accepted by Flagsmith", n_bad == 0, f"{n_posts} batches, {n_bad} not 2xx")

    if flagsmith:
        r_all = rates(attackers)
        for arm in WEIGHTS:
            fs = flagsmith.get(arm, {})
            check(f"Flagsmith exposures = enrolments ({arm})", fs.get("exposures") == r_all[arm][0],
                  f"Flagsmith {fs.get('exposures')}, controller {r_all[arm][0]}")
            check(f"Flagsmith conversions = came_back ({arm})", fs.get("conversions") == r_all[arm][1],
                  f"Flagsmith {fs.get('conversions')}, controller {r_all[arm][1]}")
    else:
        out.append("  [----] Flagsmith comparison skipped (no --flagsmith file)")

    done = closed(attackers, now)
    ctrl = {k: a for k, a in done.items() if arm_of(a) == "control"}
    even = [a for k, a in ctrl.items() if int(k[-1], 16) % 2 == 0]
    odd = [a for k, a in ctrl.items() if int(k[-1], 16) % 2 == 1]
    ke, ko = sum(bool(a.get("came_back_at")) for a in even), sum(bool(a.get("came_back_at")) for a in odd)
    p_aa = two_prop_p(len(even), ke, len(odd), ko)
    out.append(f"  [info] A/A noise floor (control, even vs odd identity): {ke}/{len(even)} vs {ko}/{len(odd)}, p = {p_aa:.2f}")
    out.append(f"\nGATE: {'PASS' if ok else 'FAIL'}")

    out.append(f"\nRESULTS (only attackers whose window has closed: {len(done)} of {len(attackers)})")
    comparison("Primary: one unit per address", done, out)
    comparison("Robustness: one unit per /24", one_per(done, "net"), out)
    comparison("Robustness: one unit per network operator (ASN)", one_per(done, "asn"), out)
    return "\n".join(out), ok


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="data")
    ap.add_argument("--flagsmith", help="JSON of exposures and conversions per arm, read from Flagsmith")
    ap.add_argument("--snapshot", help="read the published dataset (site/data/snapshot.json) instead of --data")
    ap.add_argument("--now", type=float, default=None,
                    help="Unix time to evaluate at (default: now, or the snapshot's own time)")
    a = ap.parse_args()
    fs = json.load(open(a.flagsmith)) if a.flagsmith else None
    if a.snapshot:
        attackers, totals, generated = load_snapshot(a.snapshot)
        text, ok = report(attackers, [], a.now or generated or time.time(), fs, published=totals)
    else:
        if not any(os.path.exists(os.path.join(a.data, f)) for f in ("state.json", "events.jsonl")):
            raise SystemExit(f"no controller data in {a.data!r} (no state.json or events.jsonl), so nothing to check.\n"
                             "For the published dataset: python3 -m uninvited.report --snapshot site/data/snapshot.json")
        attackers, events = load(a.data)
        # a copy of the controller's data knows returns only up to its last event: a window that closed after the copy
        # was taken must not count as "didn't come back"
        last = max((e.get("t", 0) for e in events), default=0) or None
        text, ok = report(attackers, events, min(a.now or time.time(), last or time.time()), fs)
    print(text)
    raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
