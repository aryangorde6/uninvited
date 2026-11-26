"""The controller: the only machine with keys. It follows every server's SSH log over SSH,
runs the service on each event, sends bans to every server, and talks to Flagsmith.

Run on the controller VM:  python -m uninvited.controller
Settings come from environment variables (see `fleet/controller.env.example`).
"""
import json
import logging
import os
import queue
import subprocess
import threading
import time
from datetime import datetime

from flagsmith import Flagsmith

from .asn import AsnTable, no_table
from .rules import Window
from .service import Service, State, single_instance
from .sshlog import parse_journal_line

SSH_OPTS = ["-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=4", "-o", "StrictHostKeyChecking=yes"]


class Flags:
    """The four things the service asks Flagsmith."""

    def __init__(self, key, log, feature="ban_policy", kill="ban_enforce", event="came_back", poll=30):
        self.fs = Flagsmith(environment_key=key, enable_events=True)
        self.log, self.feature, self.kill, self.event, self.poll = log, feature, kill, event, poll
        self._enforcing, self._checked = False, 0.0    # off until Flagsmith says otherwise
        self._policy = None                            # ban_policy's value for everyone; None until read

    def assign(self, ident):
        """The arm's flag value, or None if this identity is not in the running experiment."""
        flag = self.fs.get_experiment_flag(self.feature, identifier=ident)
        exp = getattr(flag, "experiment", None)
        if not (exp and getattr(exp, "in_experiment", False)):
            return None
        return flag.value

    def came_back(self, ident):
        self.fs.track_event(self.event, identifier=ident)

    def enforcing(self):
        """The kill switch, read at most every `poll` seconds; the last answer is kept if Flagsmith is down.
        The same read (environment flags, no identity, so no exposure) also refreshes `ban_policy`'s
        value for everyone, which `rollout` returns."""
        now = time.time()
        if now - self._checked >= self.poll:
            self._checked = now
            try:
                env = self.fs.get_environment_flags()
                value = bool(env.is_feature_enabled(self.kill))
            except Exception as e:
                self.log({"t": now, "what": "kill_switch_unreadable", "error": type(e).__name__})
            else:
                if value != self._enforcing:
                    self.log({"t": now, "what": "kill_switch", "enforcing": value})
                self._enforcing = value
                try:
                    flag = env.get_flag(self.feature)
                    policy = str(flag.value) if flag.enabled and flag.value is not None else None
                except Exception as e:
                    self.log({"t": now, "what": "rollout_policy_unreadable", "error": type(e).__name__})
                else:
                    if policy != self._policy:
                        self.log({"t": now, "what": "rollout_policy", "value": policy})
                    self._policy = policy
        return self._enforcing

    def rollout(self):
        """`ban_policy`'s value for everyone outside the experiment (None: flag off or not read yet)."""
        self.enforcing()
        return self._policy


class EventPosts(logging.Handler):
    """Records the HTTP status of every batch of events sent to Flagsmith, so a lost batch
    shows up in our log (the SDK keeps failed batches for its next send, but drops them at exit)."""

    def __init__(self, log):
        super().__init__(logging.DEBUG)
        self.out = log

    def emit(self, record):
        msg = record.getMessage()
        if '"POST /v1/events' in msg:
            self.out({"t": time.time(), "what": "events_post", "status": msg.rsplit('" ', 1)[-1].split(" ")[0]})


def ssh_cmd(vm, user, key, known_hosts, *remote):
    return ["ssh", *SSH_OPTS, "-o", f"UserKnownHostsFile={known_hosts}", "-i", key, "-p", str(vm["port"]),
            f"{user}@{vm['host']}", *remote]


def follow(vm, cfg, cursors, out, log):
    """Follow one server's log for ever. Each reconnect starts after the last handled line."""
    quick_fails = 0
    while True:
        started = time.time()
        log({"t": started, "what": "stream_up", "vm": vm["name"]})
        cmd = ssh_cmd(vm, "uninvited-log", cfg["log_key"], cfg["known_hosts"], cursors.get(vm["name"], ""))
        with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              text=True, errors="replace") as proc:
            for raw in proc.stdout:
                ev, cursor = parse_journal_line(raw)
                out.put((vm["name"], ev, cursor))
        log({"t": time.time(), "what": "stream_down", "vm": vm["name"]})
        quick_fails = quick_fails + 1 if time.time() - started < 30 else 0
        if quick_fails >= 3:
            cursors.pop(vm["name"], None)      # the cursor may no longer exist on the server
        time.sleep(min(60, 2 ** quick_fails))


class BanChannel:
    """One long-lived SSH session to a server's ban script. Bans wait in a queue while the
    link is down and are sent with their remaining time, so every server ends a ban together."""

    def __init__(self, vm, cfg, log):
        self.vm, self.cfg, self.log = vm, cfg, log
        self.q = queue.Queue()
        threading.Thread(target=self.run, daemon=True, name=f"ban-{vm['name']}").start()

    def send(self, ip, until):
        self.q.put((ip, until))

    def run(self):
        proc, item = None, None
        while True:
            item = item or self.q.get()
            ip, until = item
            seconds = int(until - time.time())
            if seconds <= 0:
                item = None
                continue
            try:
                if proc is None or proc.poll() is not None:
                    proc = subprocess.Popen(
                        ssh_cmd(self.vm, "uninvited-ban", self.cfg["ban_key"], self.cfg["known_hosts"]),
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
                proc.stdin.write(f"ban {ip} {seconds}\n")
                proc.stdin.flush()
                reply = proc.stdout.readline().strip()
                if not reply:
                    raise OSError("no reply")
                self.log({"t": time.time(), "what": "ban_reply", "vm": self.vm["name"], "reply": reply.split(":")[0]})
                item = None
            except (OSError, ValueError):
                self.log({"t": time.time(), "what": "ban_link_down", "vm": self.vm["name"]})
                if proc is not None:
                    proc.kill()
                proc = None
                time.sleep(5)


def read_secret(path):
    with open(path, "rb") as f:
        value = f.read().strip()
    if not value:
        raise SystemExit(f"empty secret file {path}")
    return value


def config():
    env = os.environ
    hours = int(env.get("UNINVITED_WINDOW_HOURS", "12"))      # 12-hour design, or 6
    return {
        "data": env.get("UNINVITED_DATA", "data"),
        "fleet": env["UNINVITED_FLEET"],                         # JSON list of {"name", "host", "port"}
        "flagsmith_key": read_secret(env["UNINVITED_FLAGSMITH_KEY_FILE"]).decode(),
        "hash_key": read_secret(env["UNINVITED_HASH_KEY_FILE"]),
        "log_key": env["UNINVITED_LOG_KEY"],
        "ban_key": env["UNINVITED_BAN_KEY"],
        "known_hosts": env["UNINVITED_KNOWN_HOSTS"],
        "protected": [x.strip() for x in env.get("UNINVITED_PROTECTED", "").split(",") if x.strip()],
        "enrol_from": datetime.fromisoformat(env["UNINVITED_ENROL_FROM"]).timestamp(),
        "enrol_until": datetime.fromisoformat(env["UNINVITED_ENROL_UNTIL"]).timestamp(),
        "window": Window(hours * 3600 + 300, 2 * hours * 3600 + 300),
        "asn_table": env.get("UNINVITED_ASN_TABLE", ""),           # ip2asn-v4-u32.tsv.gz; optional
    }


def main():
    cfg = config()
    os.makedirs(cfg["data"], exist_ok=True)
    lock = single_instance(os.path.join(cfg["data"], "controller.lock"))   # noqa: F841 (held for life)
    events_file = open(os.path.join(cfg["data"], "events.jsonl"), "a")
    write_lock = threading.Lock()

    def log(record):
        with write_lock:
            events_file.write(json.dumps(record) + "\n")
            events_file.flush()

    urllib3_log = logging.getLogger("urllib3.connectionpool")
    urllib3_log.setLevel(logging.DEBUG)
    urllib3_log.addHandler(EventPosts(log))

    flags = Flags(cfg["flagsmith_key"], log)
    asn = no_table
    if cfg["asn_table"]:
        try:
            asn = AsnTable(cfg["asn_table"])
        except (OSError, ValueError, EOFError) as e:      # run without it rather than not at all
            log({"t": time.time(), "what": "asn_table_error", "error": type(e).__name__})
    log({"t": time.time(), "what": "asn_table", "loaded": asn is not no_table,
         "ranges": len(asn.starts) if asn is not no_table else 0})
    with open(cfg["fleet"]) as f:
        fleet = json.load(f)
    channels = [BanChannel(vm, cfg, log) for vm in fleet]

    def ban(ip, seconds, ts):
        for channel in channels:
            channel.send(ip, ts + seconds)

    service = Service(state=State(os.path.join(cfg["data"], "state.json")), flags=flags, ban=ban, log=log,
                      hash_key=cfg["hash_key"], protected=cfg["protected"], enrol_from=cfg["enrol_from"],
                      enrol_until=cfg["enrol_until"], window=cfg["window"], asn=asn)

    cursor_path = os.path.join(cfg["data"], "cursors.json")
    cursors = json.load(open(cursor_path)) if os.path.exists(cursor_path) else {}
    lines = queue.Queue(maxsize=200_000)
    for vm in fleet:
        threading.Thread(target=follow, args=(vm, cfg, cursors, lines, log), daemon=True,
                         name=f"log-{vm['name']}").start()

    counts, last_save, last_flush, last_health = {vm["name"]: 0 for vm in fleet}, 0.0, time.time(), time.time()
    log({"t": time.time(), "what": "controller_start", "servers": len(fleet)})
    try:
        while True:
            try:
                name, ev, cursor = lines.get(timeout=5)
            except queue.Empty:
                name = ev = cursor = None
            if ev is not None:
                service.handle(name, ev)
                counts[name] += 1
            if cursor:
                cursors[name] = cursor
            flags.enforcing()                  # read the kill switch even when nobody is caught (self-throttled)
            now = time.time()
            if now - last_flush >= 60:         # send buffered came_back events (same thread as track_event)
                flags.fs.flush_events()
                last_flush = now
            if now - last_save >= 10:
                with open(cursor_path + ".tmp", "w") as f:
                    json.dump(cursors, f)
                os.replace(cursor_path + ".tmp", cursor_path)
                last_save = now
            if now - last_health >= 300:       # a heartbeat per server: a silent stream shows up here
                log({"t": now, "what": "health", "events_5min": counts, "enrolled": len(service.state.attackers),
                     "enforcing": flags.enforcing()})
                counts, last_health = {k: 0 for k in counts}, now
    finally:
        flags.fs.flush_events()
        flags.fs.close()
        log({"t": time.time(), "what": "controller_stop"})


if __name__ == "__main__":
    main()
