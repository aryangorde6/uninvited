"""Fill in a cloud-init template. Usage:
  python fleet/render.py server|controller --admin-port N --admin-ip A --controller-ip C --keys DIR > user-data
DIR holds admin.pub, log.pub and ban.pub (public halves only; private keys never leave ~/.ssh or the controller).
"""
import argparse
import base64
import ipaddress
import pathlib
import re

HERE = pathlib.Path(__file__).parent
PUBKEY = re.compile(r"ssh-ed25519 [A-Za-z0-9+/=]{60,80}( [\w.@-]{0,40})?")


def b64(name):
    return base64.b64encode((HERE / name).read_bytes()).decode()


def pubkey(path):
    key = pathlib.Path(path).read_text().strip()
    if not PUBKEY.fullmatch(key):
        raise SystemExit(f"{path}: expected one ed25519 public key")
    return key


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("kind", choices=["server", "controller"])
    ap.add_argument("--admin-port", type=int, required=True)
    ap.add_argument("--admin-ip", required=True)
    ap.add_argument("--controller-ip", default="")
    ap.add_argument("--keys", required=True)
    a = ap.parse_args()
    if not 1024 < a.admin_port < 65536:
        raise SystemExit("admin port must be 1025-65535")
    never = [str(ipaddress.IPv4Address(a.admin_ip))]
    if a.kind == "server":
        never.append(str(ipaddress.IPv4Address(a.controller_ip)))
    keys = pathlib.Path(a.keys)
    values = {
        "ADMIN_PORT": str(a.admin_port),
        "ADMIN_PUBKEY": pubkey(keys / "admin.pub"),
        "CONTROLLER_IP": a.controller_ip,
        "NEVER_BAN_LINES": "\n      ".join(never),
    }
    if a.kind == "server":
        nft = (HERE / "uninvited.nft").read_text().replace("NEVER_BAN", ", ".join(never))
        values.update({
            "LOG_PUBKEY": pubkey(keys / "log.pub"), "BAN_PUBKEY": pubkey(keys / "ban.pub"),
            "NFT_B64": base64.b64encode(nft.encode()).decode(),
            "BAN_B64": b64("uninvited-ban"), "LOG_B64": b64("uninvited-log"),
        })
    text = (HERE / f"{a.kind}-cloud-init.yaml").read_text()
    for k, v in values.items():
        text = text.replace("{{" + k + "}}", v)
    if "{{" in text:
        raise SystemExit("unfilled placeholder: " + re.search(r"\{\{\w+\}\}", text)[0])
    print(text, end="")


if __name__ == "__main__":
    main()
