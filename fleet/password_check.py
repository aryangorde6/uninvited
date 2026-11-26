"""Before go-live: try common username and password pairs on a server's port 22 and expect
every one to be refused. Run from the admin's machine (its address is never banned).
  python fleet/password_check.py HOST [N]
"""
import os
import stat
import subprocess
import sys
import tempfile

USERS = ["root", "admin", "ubuntu", "test", "user", "oracle", "postgres", "guest", "ftpuser", "pi"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "123", "1234", "test", "ubuntu"]


def try_pair(host, user, password):
    with tempfile.TemporaryDirectory() as d:
        askpass = os.path.join(d, "askpass")
        with open(askpass, "w") as f:
            f.write("#!/bin/sh\nprintf '%s\\n' \"$UNINVITED_TRY\"\n")
        os.chmod(askpass, stat.S_IRWXU)
        env = dict(os.environ, SSH_ASKPASS=askpass, SSH_ASKPASS_REQUIRE="force", UNINVITED_TRY=password)
        r = subprocess.run(["ssh", "-o", "PreferredAuthentications=password", "-o", "PubkeyAuthentication=no",
                            "-o", "NumberOfPasswordPrompts=1", "-o", "StrictHostKeyChecking=no",
                            "-o", "UserKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-p", "22",
                            f"{user}@{host}", "true"], env=env, stdin=subprocess.DEVNULL,
                           capture_output=True, text=True, timeout=30)
        return r.returncode == 0, r.stderr.strip().splitlines()[-1:] or [""]


def main():
    host, n = sys.argv[1], int(sys.argv[2]) if len(sys.argv) > 2 else 100
    pairs = [(u, p) for u in USERS for p in PASSWORDS][:n]
    accepted = []
    for user, password in pairs:
        ok, last = try_pair(host, user, password)
        if ok:
            accepted.append(user)
    print(f"{len(pairs)} pairs tried, {len(accepted)} accepted")
    if accepted:
        raise SystemExit("FAIL: a password worked; take the server down now")
    print("PASS: every pair refused")


if __name__ == "__main__":
    main()
