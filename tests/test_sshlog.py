import json

from uninvited.sshlog import Event, parse_journal_line, parse_message

T = 1_764_000_000.0


def sshd(msg):
    return parse_message(msg, T, "sshd")


def test_failed_password_valid_and_invalid_user():
    assert sshd("Failed password for root from 203.0.113.9 port 51234 ssh2") == Event("failed", "203.0.113.9", 51234, T)
    assert sshd("Failed password for invalid user admin from 203.0.113.9 port 2 ssh2").kind == "failed_invalid"
    assert sshd("Failed none for invalid user  from 203.0.113.9 port 2 ssh2").kind == "failed_invalid"


def test_invalid_user_line():
    assert sshd("Invalid user oracle from 198.51.100.7 port 40000") == Event("invalid_user", "198.51.100.7", 40000, T)
    assert sshd("Invalid user  from 198.51.100.7 port 40000").ip == "198.51.100.7"   # empty username


def test_hostile_username_cannot_frame_another_ip():
    # the attacker at 198.51.100.7 picks a username that contains a different address
    msg = "Failed password for invalid user x from 203.0.113.9 port 22 ssh2 from 198.51.100.7 port 4444 ssh2"
    assert sshd(msg).ip == "198.51.100.7"
    msg = "Invalid user y from 203.0.113.9 port 1 from 198.51.100.7 port 4444"
    assert sshd(msg).ip == "198.51.100.7"
    msg = "Connection closed by invalid user z 203.0.113.9 port 1 [preauth] 198.51.100.7 port 9 [preauth]"
    assert sshd(msg).ip == "198.51.100.7"


def test_lines_with_extra_text_or_newlines_are_ignored():
    assert sshd("Failed password for root from 203.0.113.9 port 2 ssh2 trailing") is None
    assert sshd("Failed password for root from 203.0.113.9 port 2 ssh2\n") is None
    assert sshd("x\nFailed password for root from 203.0.113.9 port 2 ssh2") is None
    assert sshd("Failed password for root from 999.1.1.1 port 2 ssh2") is None
    assert sshd("Failed password for root from 01.2.3.4 port 2 ssh2") is None
    assert sshd("Failed password for root from 1.2.3.4 port 70000 ssh2") is None
    assert sshd("Accepted publickey for ubuntu from 203.0.113.9 port 2 ssh2: ED25519 SHA256:abc") is None
    assert sshd("Failed password for root from 2001:db8::1 port 2 ssh2") is None   # IPv6 is out of scope


def test_activity_lines():
    for msg in [
        "Connection closed by 203.0.113.9 port 2 [preauth]",
        "Connection reset by 203.0.113.9 port 2 [preauth]",
        "Connection closed by authenticating user root 203.0.113.9 port 2 [preauth]",
        "Disconnected from invalid user bob 203.0.113.9 port 2 [preauth]",
        "Received disconnect from 203.0.113.9 port 2:11: Bye Bye [preauth]",
        "banner exchange: Connection from 203.0.113.9 port 2: invalid format",
        "Unable to negotiate with 203.0.113.9 port 2: no matching key exchange method found.",
    ]:
        ev = sshd(msg)
        assert ev is not None and ev.kind == "activity" and ev.ip == "203.0.113.9", msg


def test_firewall_drop_line():
    msg = ("uninvited-drop: IN=ens5 OUT= MAC=0a:00 SRC=203.0.113.9 DST=172.31.5.6 LEN=60 TOS=0x00 PREC=0x00 "
           "TTL=50 ID=1 DF PROTO=TCP SPT=40000 DPT=22 WINDOW=64240 RES=0x00 SYN URGP=0")
    assert parse_message(msg, T, "kernel") == Event("dropped", "203.0.113.9", 0, T)
    assert parse_message(msg, T, "sshd") is None
    assert parse_message("other: " + msg, T, "kernel") is None


def journal(**fields):
    base = {"__REALTIME_TIMESTAMP": str(int(T * 1_000_000)), "__CURSOR": "s=ab;i=1"}
    base.update(fields)
    return json.dumps(base)


def test_journal_source_is_checked_with_trusted_fields():
    msg = "Failed password for root from 203.0.113.9 port 2 ssh2"
    ev, cursor = parse_journal_line(journal(MESSAGE=msg, _SYSTEMD_UNIT="ssh.service"))
    assert ev.kind == "failed" and ev.ts == T and cursor == "s=ab;i=1"
    ev, _ = parse_journal_line(journal(MESSAGE=msg, SYSLOG_IDENTIFIER="sshd", _SYSTEMD_UNIT="user@1000.service"))
    assert ev is None


def test_journal_byte_array_message_and_garbage():
    msg = list("Invalid user \xff from 203.0.113.9 port 7".encode("latin-1"))
    ev, _ = parse_journal_line(journal(MESSAGE=msg, _SYSTEMD_UNIT="ssh.service"))
    assert ev.kind == "invalid_user"
    assert parse_journal_line("not json") == (None, None)
    assert parse_journal_line("[1,2]") == (None, None)
    assert parse_journal_line(journal(MESSAGE=None, _SYSTEMD_UNIT="ssh.service"))[0] is None
