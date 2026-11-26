"""Add each server's SSH host key to data/known_hosts, read from AWS's console output
(a channel the server can't fake to us), so the first connection is already verified.
  python fleet/hostkeys.py          # waits up to 10 minutes for servers still booting
"""
import json
import pathlib
import re
import subprocess
import time

DATA = pathlib.Path(__file__).parent.parent / "data"
KEY = re.compile(r"^(ssh-ed25519 [A-Za-z0-9+/=]+)", re.M)


def console(region, instance_id):
    return subprocess.run(["aws", "--profile", "hackathon", "--region", region, "ec2", "get-console-output",
                           "--instance-id", instance_id, "--latest", "--query", "Output", "--output", "text"],
                          capture_output=True, text=True).stdout


def instance_ids():
    out = {}
    for region in {vm["region"] for vm in json.loads((DATA / "fleet.json").read_text())}:
        res = json.loads(subprocess.run(
            ["aws", "--profile", "hackathon", "--region", region, "ec2", "describe-instances", "--filters",
             "Name=tag:Project,Values=uninvited", "Name=instance-state-name,Values=running", "--output", "json"],
            capture_output=True, text=True, check=True).stdout)
        for r in res["Reservations"]:
            for i in r["Instances"]:
                out[i.get("PublicIpAddress")] = (region, i["InstanceId"])
    return out


def main():
    fleet = json.loads((DATA / "fleet.json").read_text())
    known_path = DATA / "known_hosts"
    known = known_path.read_text() if known_path.exists() else ""
    ids = instance_ids()
    todo = [vm for vm in fleet if f"[{vm['host']}]:{vm['port']} " not in known]
    deadline = time.time() + 600
    while todo and time.time() < deadline:
        for vm in list(todo):
            text = console(*ids[vm["host"]])
            if "END SSH HOST KEY KEYS" not in text:
                continue
            block = text.split("BEGIN SSH HOST KEY KEYS", 1)[1].split("END SSH HOST KEY KEYS", 1)[0]
            m = KEY.search(block)
            if m:
                with open(known_path, "a") as f:
                    f.write(f"[{vm['host']}]:{vm['port']} {m[1]}\n")
                todo.remove(vm)
                print("host key saved:", vm["name"], flush=True)
        if todo:
            time.sleep(15)
    print("missing:", [vm["name"] for vm in todo] if todo else "none")


if __name__ == "__main__":
    main()
