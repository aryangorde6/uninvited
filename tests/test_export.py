import json

import pytest

from uninvited.export import WINDOW_START, dumps_checked, snapshot

H = 3600
T0 = 1795690000.0                                    # 26 Nov 2026, 4:16 PM IST, during enrolment


def attacker(arm, first, back=0.0):
    return {"arm": arm, "seconds": int(arm), "first_catch": first, "first_vm": "server-eu-central-1-14",
            "came_back_at": back, "net": "net-ab12", "asn": 64500, "country": "DE"}


def test_counts_windows_and_arms():
    att = {"ip-aaa": attacker("0", T0, back=T0 + 13 * H),      # closed window, came back
           "ip-bbb": attacker("600", T0),                       # closed window, stayed away
           "ip-ccc": attacker("43200", T0 + 20 * H)}            # window not started
    events = [{"what": "dropped", "id": "ip-bbb", "t": T0 + 60},
              {"what": "dropped", "id": "ip-bbb", "t": T0 + 120},
              {"what": "banned", "id": "ip-bbb", "t": T0},
              {"what": "failed", "id": "ip-aaa", "t": T0 + 13 * H},
              {"what": "came_back", "id": "ip-aaa", "t": T0 + 13 * H},
              {"what": "ban_reply", "reply": "ok"}, {"what": "ban_reply", "reply": "refused"},
              {"what": "events_post", "status": "202"},
              {"what": "health", "t": T0 + 300, "events_5min": {"server-us-west-2-12": 4, "server-sa-east-1-48": 1}}]
    snap = snapshot(att, events, T0 + 25 * H)
    rows = {r["id"]: r for r in snap["attackers"]}
    assert rows["ip-aaa"]["came_back_hours"] == 13.0 and rows["ip-aaa"]["window"] == "closed"
    assert rows["ip-bbb"]["came_back_hours"] is None and rows["ip-bbb"]["dropped"] == 2 and rows["ip-bbb"]["bans"] == 1
    assert rows["ip-ccc"]["window"] == "not started" and rows["ip-ccc"]["arm"] == "ban_12h"
    per = snap["totals"]["per_arm"]
    assert per["control"] == {"enrolled": 1, "closed": 1, "came_back": 1}
    assert per["ban_10m"] == {"enrolled": 1, "closed": 1, "came_back": 0}
    assert per["ban_12h"] == {"enrolled": 1, "closed": 0, "came_back": 0}
    assert snap["totals"]["ban_replies_ok"] == 1 and snap["totals"]["ban_replies_other"] == 1
    assert {s["name"]: s["region"] for s in snap["servers"]} == {"server-sa-east-1-48": "sa-east-1",
                                                                  "server-us-west-2-12": "us-west-2"}
    assert snap["gate"]["pass"] is True


def test_window_opens_at_12h05m():
    att = {"ip-ddd": attacker("0", T0)}
    assert snapshot(att, [], T0 + WINDOW_START - 1)["attackers"][0]["window"] == "not started"
    assert snapshot(att, [], T0 + WINDOW_START)["attackers"][0]["window"] == "open"


def test_only_published_fields_leave():
    att = {"ip-eee": dict(attacker("0", T0), secret_field="x")}
    row = snapshot(att, [{"what": "failed", "id": "ip-eee", "why": "anything", "t": T0}], T0)["attackers"][0]
    assert "secret_field" not in row and "why" not in json.dumps(row)


def test_refuses_anything_like_an_address():
    with pytest.raises(SystemExit):
        dumps_checked({"note": "seen from 203.0.113.7"})
    assert "1.5" in dumps_checked({"version": "1.5", "hours": 12.08})
