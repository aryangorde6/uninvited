"""Turn one server's journal lines into events about IPv4 addresses.

Every username in SSH's log is chosen by an attacker. A username such as
"x from 203.0.113.9 port 22 ssh2" must never make us blame 203.0.113.9.
So each pattern either ends at the end of the line (the real IP is always the
last one sshd writes) or puts the IP straight after fixed text at the start,
before any attacker text. Lines that fit no pattern exactly are ignored.
"""
import ipaddress
import json
import re
from dataclasses import dataclass

IP = r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
PORT = r"(?P<port>\d{1,5})"
USER = r"(?:(?:invalid|authenticating) user .* )?"

# Failed logins. re.fullmatch is used, and "." never matches a newline.
FAILED = re.compile(
    rf"Failed (?:password|none|keyboard-interactive/pam) for (?P<invalid>invalid user )?.* from {IP} port {PORT} ssh2"
)
INVALID_USER = re.compile(rf"Invalid user .* from {IP} port {PORT}")

# Other signs that an address reached port 22 (they count as "came back", not as failures).
ACTIVITY_END = [
    re.compile(rf"Connection (?:closed|reset) by {USER}{IP} port {PORT} \[preauth\]"),
    re.compile(rf"Disconnected from {USER}{IP} port {PORT} \[preauth\]"),
]
ACTIVITY_START = [  # the IP follows fixed text at the start; attacker text, if any, comes after it
    re.compile(rf"Received disconnect from {IP} port {PORT}:"),
    re.compile(rf"banner exchange: Connection from {IP} port {PORT}:"),
    re.compile(rf"Unable to negotiate with {IP} port {PORT}:"),
]

# The firewall logs (at most once a minute per address) a packet to port 22 dropped by a ban.
DROP_PREFIX = "uninvited-drop: "
DROP = re.compile(rf"\bSRC={IP} DST=\S+ .*\bPROTO=TCP SPT=\d+ DPT=22\b")


@dataclass(frozen=True)
class Event:
    kind: str     # "failed", "failed_invalid", "invalid_user", "activity" or "dropped"
    ip: str
    port: int     # the attacker's source port (0 for dropped packets)
    ts: float     # seconds since the epoch, from the journal


def valid_ipv4(text):
    """Return the address as a string if it is a well-formed public-looking IPv4, else None."""
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def parse_message(message, ts, source):
    """One journal MESSAGE -> an Event, or None. `source` is "sshd" or "kernel"."""
    if source == "kernel":
        if not message.startswith(DROP_PREFIX):
            return None
        m = DROP.search(message)
        if m and valid_ipv4(m["ip"]):
            return Event("dropped", valid_ipv4(m["ip"]), 0, ts)
        return None

    m = FAILED.fullmatch(message)
    if m:
        kind = "failed_invalid" if m["invalid"] else "failed"
    else:
        m = INVALID_USER.fullmatch(message)
        kind = "invalid_user"
    if not m:
        kind = "activity"
        m = next((p.fullmatch(message) for p in ACTIVITY_END if p.fullmatch(message)), None)
        if not m:
            m = next((p.match(message) for p in ACTIVITY_START if p.match(message)), None)
    if not m:
        return None
    ip, port = valid_ipv4(m["ip"]), int(m["port"])
    if ip is None or not 0 < port < 65536:
        return None
    return Event(kind, ip, port, ts)


def parse_journal_line(raw):
    """One line of `journalctl -o json` -> (Event or None, cursor or None).

    Only trusted journal fields (those starting with "_", set by journald itself)
    decide where a message came from, so a fake "sshd" message is ignored.
    """
    try:
        entry = json.loads(raw)
    except ValueError:
        return None, None
    if not isinstance(entry, dict):
        return None, None
    cursor = entry.get("__CURSOR")
    message = entry.get("MESSAGE")
    if isinstance(message, list):  # journald sends non-UTF-8 messages as a list of bytes
        try:
            message = bytes(message).decode("utf-8", "replace")
        except (TypeError, ValueError):
            return None, cursor
    if not isinstance(message, str):
        return None, cursor
    try:
        ts = int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
    except (KeyError, TypeError, ValueError):
        return None, cursor
    if entry.get("_TRANSPORT") == "kernel":
        source = "kernel"
    elif entry.get("_SYSTEMD_UNIT") == "ssh.service":
        source = "sshd"
    else:
        return None, cursor
    return parse_message(message, ts, source), cursor
