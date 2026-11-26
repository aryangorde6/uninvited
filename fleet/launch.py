"""Start, list and stop the fleet on AWS, with hard limits in code.

  python fleet/launch.py check                      # read-only: budget, prices, what would start
  python fleet/launch.py controller --spend-ok      # one t4g.micro
  python fleet/launch.py servers 10 --spend-ok      # t4g.nano servers, spread over REGIONS
  python fleet/launch.py list
  python fleet/launch.py stop                       # stops (not deletes) every Uninvited instance

Limits that no argument can lift: at most MAX_SERVERS servers and one controller, only the two
smallest ARM types, and nothing starts unless an AWS budget with alerts exists that counts spend
before credits (a budget that subtracts credits reads $0 and never fires). Every instance also
powers itself off after 4 days (cloud-init). Deleting instances is left to a person.
"""
import argparse
import ipaddress
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.request

PROFILE = "hackathon"
HOME_REGION = "eu-central-1"
REGIONS = ["us-east-1", "eu-central-1", "ap-southeast-1", "us-west-2",   # not Mumbai, so the budget counts only Uninvited
           # added 26 Nov: AWS allows 8 small servers in each region above and 2 in each region below
           "us-east-2", "us-west-1", "ca-central-1", "eu-west-1", "eu-west-2", "eu-north-1",
           "ap-northeast-1", "ap-southeast-2", "sa-east-1"]
MAX_SERVERS = 48                 # raised 12 -> 24 -> 48 on 26 Nov (Aryan's OK each time): attack volume far below plan
TYPES = {"server": "t4g.nano", "controller": "t4g.micro"}
AMI_PARAM = "/aws/service/canonical/ubuntu/server/24.04/stable/current/arm64/hvm/ebs-gp3/ami-id"
TAG = "uninvited"
HERE = pathlib.Path(__file__).parent
DATA = HERE.parent / "data"


def aws(*args, region=HOME_REGION):
    out = subprocess.run(["aws", "--profile", PROFILE, "--region", region, "--output", "json", *args],
                         check=True, capture_output=True, text=True).stdout
    return json.loads(out) if out.strip() else {}


def instances(region, states=("pending", "running", "stopping", "stopped")):
    res = aws("ec2", "describe-instances", "--filters", f"Name=tag:Project,Values={TAG}",
              f"Name=instance-state-name,Values={','.join(states)}", region=region)
    found = []
    for r in res["Reservations"]:
        for i in r["Instances"]:
            tags = {t["Key"]: t["Value"] for t in i.get("Tags", [])}
            found.append({"id": i["InstanceId"], "region": region, "role": tags.get("Role"), "name": tags.get("Name"),
                          "state": i["State"]["Name"], "ip": i.get("PublicIpAddress")})
    return found


def guard_budget():
    """Refuse to spend unless a budget with alerts counts spend before credits."""
    account = aws("sts", "get-caller-identity")["Account"]
    for b in aws("budgets", "describe-budgets", "--account-id", account).get("Budgets", []):
        if b["BudgetType"] != "COST" or b.get("CostTypes", {}).get("IncludeCredit", True):
            continue
        notes = aws("budgets", "describe-notifications-for-budget", "--account-id", account,
                    "--budget-name", b["BudgetName"]).get("Notifications", [])
        if notes:
            return f"{b['BudgetName']} (${b['BudgetLimit']['Amount']} a {b['TimeUnit'].lower()}, credits not subtracted)"
    raise SystemExit("REFUSED: no AWS cost budget with alerts that leaves credits out. Aryan sets one in the "
                     "AWS console (Budgets > Create, untick 'Credits' under advanced options), then run again.")


def my_ip():
    with urllib.request.urlopen("https://checkip.amazonaws.com", timeout=10) as r:
        return str(ipaddress.IPv4Address(r.read().decode().strip()))


def security_group(region, role, admin_port, sources):
    """One group per role and region: port 22 open to all on servers; the admin port only to `sources`."""
    name = f"{TAG}-{role}"
    vpc = aws("ec2", "describe-vpcs", "--filters", "Name=isDefault,Values=true", region=region)["Vpcs"][0]["VpcId"]
    found = aws("ec2", "describe-security-groups", "--filters", f"Name=group-name,Values={name}",
                f"Name=vpc-id,Values={vpc}", region=region)["SecurityGroups"]
    if found:
        return found[0]["GroupId"]
    gid = aws("ec2", "create-security-group", "--group-name", name, "--vpc-id", vpc,
              "--description", f"Uninvited {role}", region=region)["GroupId"]
    rules = [{"IpProtocol": "tcp", "FromPort": admin_port, "ToPort": admin_port,
              "IpRanges": [{"CidrIp": f"{ip}/32"} for ip in sources]}]
    if role == "server":
        rules.append({"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]})
    aws("ec2", "authorize-security-group-ingress", "--group-id", gid, "--ip-permissions", json.dumps(rules), region=region)
    # outbound: only package updates (80, 443), plus the admin port for the controller to reach servers
    aws("ec2", "revoke-security-group-egress", "--group-id", gid, "--ip-permissions",
        json.dumps([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}]), region=region)
    out = [{"IpProtocol": "tcp", "FromPort": p, "ToPort": p, "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}
           for p in ([80, 443, admin_port] if role == "controller" else [80, 443])]
    aws("ec2", "authorize-security-group-egress", "--group-id", gid, "--ip-permissions", json.dumps(out), region=region)
    return gid


def launch(region, role, count, user_data, gid, first_index):
    ami = aws("ssm", "get-parameter", "--name", AMI_PARAM, region=region)["Parameter"]["Value"]
    ids = []
    for n in range(count):
        name = f"{role}-{region}-{first_index + n}"
        tags = json.dumps([{"ResourceType": "instance", "Tags": [
            {"Key": "Project", "Value": TAG}, {"Key": "Role", "Value": role}, {"Key": "Name", "Value": name}]}])
        res = aws("ec2", "run-instances", "--image-id", ami, "--instance-type", TYPES[role], "--count", "1",
                  "--security-group-ids", gid, "--user-data", f"file://{user_data}",
                  "--metadata-options", "HttpTokens=required,HttpEndpoint=enabled",
                  "--tag-specifications", tags, region=region)
        ids.append(res["Instances"][0]["InstanceId"])
    aws("ec2", "wait", "instance-running", "--instance-ids", *ids, region=region)
    return ids


def render(kind, admin_port, admin_ip, controller_ip, keys):
    path = DATA / f"{kind}-user-data.yaml"
    with open(path, "w") as f:
        subprocess.run([sys.executable, str(HERE / "render.py"), kind, "--admin-port", str(admin_port),
                        "--admin-ip", admin_ip, "--controller-ip", controller_ip, "--keys", keys],
                       check=True, stdout=f)
    return path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("command", choices=["check", "controller", "servers", "list", "stop"])
    ap.add_argument("count", nargs="?", type=int, default=0)
    ap.add_argument("--spend-ok", action="store_true", help="Aryan has OK'd the cloud spend")
    ap.add_argument("--admin-port", type=int, default=int(os.environ.get("UNINVITED_ADMIN_PORT", "0")))
    ap.add_argument("--keys", default=str(DATA / "pubkeys"))
    a = ap.parse_args()
    DATA.mkdir(exist_ok=True)
    everything = [i for r in REGIONS for i in instances(r)]

    if a.command == "list":
        for i in everything:
            print(i)
        return
    if a.command == "stop":
        for r in REGIONS:
            ids = [i["id"] for i in everything if i["region"] == r and i["state"] in ("pending", "running")]
            if ids:
                aws("ec2", "stop-instances", "--instance-ids", *ids, region=r)
                print(f"stopping {len(ids)} in {r}")
        return

    print("budget:", guard_budget())
    servers = [i for i in everything if i["role"] == "server"]
    controllers = [i for i in everything if i["role"] == "controller"]
    if a.command == "check":
        print(f"running or stopped now: {len(servers)} servers, {len(controllers)} controller(s); cap {MAX_SERVERS}")
        return
    if not a.spend_ok:
        raise SystemExit("REFUSED: pass --spend-ok only after Aryan has OK'd the cloud spend")
    if not 1024 < a.admin_port < 65536:
        raise SystemExit("set --admin-port (1025-65535)")
    admin_ip = my_ip()

    if a.command == "controller":
        if controllers:
            raise SystemExit("REFUSED: a controller already exists")
        gid = security_group(HOME_REGION, "controller", a.admin_port, [admin_ip])
        ud = render("controller", a.admin_port, admin_ip, "", a.keys)
        ids = launch(HOME_REGION, "controller", 1, ud, gid, 1)
        print("controller", ids, instances(HOME_REGION, ("running",)))
        return

    if not controllers or not controllers[0]["ip"]:
        raise SystemExit("start the controller first: servers only accept its address")
    if a.count < 1 or len(servers) + a.count > MAX_SERVERS:
        raise SystemExit(f"REFUSED: {len(servers)} servers exist; at most {MAX_SERVERS} in all")
    controller_ip = controllers[0]["ip"]
    ud = render("server", a.admin_port, admin_ip, controller_ip, a.keys)
    for k in range(a.count):
        region = REGIONS[(len(servers) + k) % len(REGIONS)]
        gid = security_group(region, "server", a.admin_port, [admin_ip, controller_ip])
        print(region, launch(region, "server", 1, ud, gid, len(servers) + k + 1))
    time.sleep(1)
    fleet = [{"name": i["name"], "host": i["ip"], "port": a.admin_port, "region": i["region"]}
             for r in REGIONS for i in instances(r, ("running",)) if i["role"] == "server"]
    (DATA / "fleet.json").write_text(json.dumps(fleet, indent=1))
    print(f"{len(fleet)} servers written to data/fleet.json")


if __name__ == "__main__":
    main()
