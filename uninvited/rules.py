"""The pure decisions, with no network: what counts as a catch, how long an arm bans,
which identity an IP gets, and when an attacker has "come back".
"""
import hashlib
import hmac
import ipaddress
from collections import OrderedDict, deque

MAX_BAN = 12 * 3600          # a flag value can never ban for longer than this
MAXRETRY, FINDTIME = 5, 600  # fail2ban's defaults: five failures in ten minutes


class CatchRule:
    """Counts failed logins per (server, IP) and reports a catch at five within ten minutes.

    One login attempt is one failure. sshd logs an attempt on an unknown user twice
    ("Invalid user ..." and then "Failed password for invalid user ..." on the same
    connection), so the second line of that pair is not counted again.
    """

    def __init__(self, maxretry=MAXRETRY, findtime=FINDTIME, max_tracked=200_000):
        self.maxretry, self.findtime, self.max_tracked = maxretry, findtime, max_tracked
        self.fails = {}                     # (vm, ip) -> deque of failure times
        self.open_invalid = OrderedDict()   # (vm, ip, port) whose "Invalid user" line was counted

    def feed(self, vm, ev):
        """Returns True if this event completes a catch."""
        if ev.kind == "invalid_user":
            self.open_invalid[(vm, ev.ip, ev.port)] = None
            if len(self.open_invalid) > self.max_tracked:
                self.open_invalid.popitem(last=False)
        elif ev.kind == "failed_invalid":
            key = (vm, ev.ip, ev.port)
            if key in self.open_invalid:
                del self.open_invalid[key]
                return False                # same attempt as its "Invalid user" line
        elif ev.kind != "failed":
            return False
        times = self.fails.setdefault((vm, ev.ip), deque())
        times.append(ev.ts)
        while times and times[0] <= ev.ts - self.findtime:
            times.popleft()
        if len(times) >= self.maxretry:
            del self.fails[(vm, ev.ip)]     # start counting afresh, as fail2ban does after a ban
            return True
        if len(self.fails) > self.max_tracked:
            self.prune(ev.ts)
        return False

    def prune(self, now):
        for key in [k for k, t in self.fails.items() if not t or t[-1] <= now - self.findtime]:
            del self.fails[key]


def ban_seconds(value):
    """A flag value -> ban length in seconds. Anything odd means "don't ban"; never above MAX_BAN."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, str):
        value = value.strip()
        if not value.isdigit():
            return 0                        # "none", "", "-5", "1e9", ...
        value = int(value)
    if not isinstance(value, int) or value <= 0:
        return 0
    return min(value, MAX_BAN)


def identity(ip, key):
    """The Flagsmith identifier for an IP: a keyed hash, so the address can't be recovered
    without the key (an unkeyed hash of an IPv4 address can be reversed in minutes)."""
    return "ip-" + hmac.new(key, ip.encode(), hashlib.sha256).hexdigest()[:20]


def network(ip, key):
    """A keyed hash of the IP's /24, for the pre-registered rerun with one unit per network.
    Kept so the network survives without storing any address or prefix."""
    net = ipaddress.IPv4Network(f"{ip}/24", strict=False)
    return "net-" + hmac.new(key, b"net24:" + str(net).encode(), hashlib.sha256).hexdigest()[:12]


def never_ban(ip, protected):
    """True for the admin's and controller's addresses and for every non-public range."""
    addr = ipaddress.IPv4Address(ip)
    return ip in protected or not addr.is_global or addr.is_multicast


class Window:
    """When a return counts as `came_back`: [start, end) seconds after the first catch.
    12-hour design: 12h05m to 24h05m, so it opens after the longest ban (12 h) has ended."""

    def __init__(self, start=12 * 3600 + 300, end=24 * 3600 + 300):
        self.start, self.end = start, end

    def contains(self, first_catch, ts):
        return self.start <= ts - first_catch < self.end
