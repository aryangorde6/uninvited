# Uninvited

**Is fail2ban's 10-minute ban enough?** Every attacker who brute-forces SSH on a small fleet of real servers becomes one user in a Flagsmith experiment. A flag decides how long that attacker is banned from the whole fleet (no ban, 10 minutes, or 12 hours), and Flagsmith measures who comes back 12–24 hours later, after every ban has ended.

> Work in progress during Toggle Wars (26–29 Nov 2026). The result, the video and the website link go here.

## For judges

- **The question:** does banning an attacker for fail2ban's default 10 minutes lower the share who come back 12–24 hours later, compared with no ban?
- **The users are real.** Nobody here is simulated: every identity is an IP address that tried to log in to one of our servers.
- **Result:** _pending (the experiment is running)._

## How Flagsmith is used

| Flagsmith part | What it does here |
|---|---|
| Multivariate flag `ban_policy` | Holds the ban length for every server: `0` (no ban), `600` (10 minutes), `43200` (12 hours). Flagsmith assigns each attacker an arm. |
| `get_experiment_flag` | Called once per newly caught attacker, with a keyed hash of its IP as the identity; records the exposure. |
| Event `came_back` | Sent with `track_event` the first time the attacker reaches port 22 again, 12h05m–24h05m after it was first caught. |
| Experiment | `came_back` as the primary metric, lower is better. Its results page gives the win probability. |
| Flag `ban_enforce` | The kill switch: off means no new enrolments and no new bans on any server. |
| Rollout | At the end the winning ban length is set for everyone with the same `ban_policy` flag, and every server applies it. |

## How it works

- **Servers** run stock OpenSSH on port 22 with a password prompt nobody can pass (every password is locked). A small firewall table holds bans that expire by themselves.
- **One controller** holds every key. It follows each server's SSH log over SSH (a key that can only stream the log) and sends bans back (a key that can only run a ban script that accepts `ban <IPv4> <seconds>`).
- **A catch** is five failed logins within ten minutes from one IP on one server, as fail2ban counts them.
- IPs are stored only as keyed hashes (plus a keyed hash of the /24, and the network operator's ASN and country, looked up once at enrolment). Usernames that attackers type are never stored or shown.

## Setup

**You need:** an AWS account with the AWS CLI (profile `hackathon`, or change `PROFILE` in `fleet/launch.py`) and a cost budget with alerts that does not subtract credits (the launcher refuses to start anything without one); a Flagsmith account (the free Cloud plan works) with its managed warehouse turned on; Python 3.10+ and [uv](https://docs.astral.sh/uv/).

**1. Flagsmith** (one environment):
- multivariate flag `ban_policy`: control value `0`, variations `ban_10m` = `600` and `ban_12h` = `43200`, each with a label;
- flag `ban_enforce`, off;
- metric `came_back`: occurrence, lower is better, event name `came_back`;
- a server-side environment key, saved to a file only you can read.

**2. Your admin key:** `ssh-keygen -t ed25519 -f ~/.ssh/uninvited_admin`, then copy the `.pub` file to `data/pubkeys/admin.pub` (`data/` is git-ignored). Pick an admin port `PORT` (1025–65535); it is opened only to your address.

**3. The controller:**
```bash
uv venv && uv pip install -e . pytest
.venv/bin/python fleet/launch.py check                              # read-only: budget found, what exists
.venv/bin/python fleet/launch.py controller --spend-ok --admin-port PORT
```
Copy this repository to `/opt/uninvited` on the controller and run `sudo sh /opt/uninvited/fleet/controller-setup.sh`. It makes the two limited SSH keys and the hashing key on the controller (no private key leaves it) and prints the two public keys: save them as `data/pubkeys/log.pub` and `data/pubkeys/ban.pub`.

**4. The servers:**
```bash
.venv/bin/python fleet/launch.py servers 12 --spend-ok --admin-port PORT   # spread over four regions
.venv/bin/python fleet/hostkeys.py                                          # host keys from AWS console output
.venv/bin/python fleet/password_check.py HOST                               # each server: expect "PASS: every pair refused"
```

**5. Start the controller:** on the controller, write `/etc/uninvited/controller.env` from `fleet/controller.env.example`, the server list `/etc/uninvited/fleet.json` (`name`, `host`, `port` per server, from `data/fleet.json`), their host keys `/etc/uninvited/ssh/known_hosts` (from `data/known_hosts`) and the Flagsmith key file, then `sudo systemctl enable --now uninvited-controller`.

**6. Start the experiment:** create the experiment on `ban_policy` in Flagsmith (rollout 100%, primary metric `came_back`), then turn `ban_enforce` on. Nobody is enrolled outside `UNINVITED_ENROL_FROM`–`UNINVITED_ENROL_UNTIL`.

**What you should see** in `/var/lib/uninvited/events.jsonl`: `controller_start`, one `stream_up` per server, `kill_switch` with `"enforcing": true`, and a `health` line every 5 minutes with events per server. When an attacker is caught inside the window: `enrolled` (hashed identity, arm, hashed /24, ASN, country), `banned`, one `ban_reply` per server, and 12–24 hours later perhaps `came_back`. In Flagsmith, the experiment's exposures rise with each enrolment.

**Check and analyse** (the integrity gate first, then the results):
```bash
cd /opt/uninvited && sudo python3 -m uninvited.report --data /var/lib/uninvited   # on the controller
python3 -m uninvited.report --data DIR --flagsmith flagsmith.json              # with Flagsmith's numbers per arm
```

**Tests:**
```bash
.venv/bin/python -m pytest
```

**Stop:** `.venv/bin/python fleet/launch.py stop` stops (does not delete) every instance; each one also powers itself off after 4 days.

## Before the hackathon / during the hackathon

- **Before 26 Nov:** the idea and plans, the art and the animated clips (see Credits), and a throwaway test of a free Flagsmith account with made-up identities (kept outside this repo).
- **During (from 26 Nov 8:00 AM IST):** all the code in this repository, the servers, and the experiment itself.

## Credits

- [OpenSSH](https://www.openssh.com/), [nftables](https://netfilter.org/projects/nftables/), the [Flagsmith Python SDK](https://github.com/Flagsmith/flagsmith-python-client).
- Network operator and country at enrolment: [iptoasn.com](https://iptoasn.com/)'s IP-to-ASN table (public domain, PDDL v1.0).
- Art: the site's and the video's images were generated with **ChatGPT**, and the short animated clips with Google's **Gemini Omni**, from prompts written for this project.

## Licence

MIT. See [LICENSE](LICENSE).

## AI tools used

This project was built with help from AI coding assistants.
