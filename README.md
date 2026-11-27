# Uninvited

**Is fail2ban's 10-minute ban enough?** fail2ban (over 19,000 stars on GitHub) bans an attacker for 10 minutes by default (`bantime = 10m` in its `jail.conf`), and I found no study of whether that keeps attackers away. So every attacker who brute-forces SSH on a fleet of 48 real servers becomes one user in a Flagsmith experiment. A flag decides how long that attacker is banned from the whole fleet (no ban, 10 minutes, or 12 hours), and Flagsmith measures who comes back 12–24 hours later, after every ban has ended.

**Website (live counts, results, method, and the replay): https://uninvited.aryangorde.com**

> The experiment ran live during Toggle Wars (26–29 Nov 2026). **Enrolment closed on Fri 27 Nov at 3:00 PM IST with 65 real attackers** (no ban 25, 10 minutes 17, 12 hours 23; the integrity gate passes). The last return window closes about Sat 28 Nov, 3:05 PM IST; the result and the video go here then.

## For judges

- **The question:** does banning an attacker for fail2ban's default 10 minutes lower the share who come back 12–24 hours later, compared with no ban? The hypothesis was committed at 1:17 PM IST on 26 Nov, before enrolment opened at 2:00 PM ([`PREREGISTRATION.md`](PREREGISTRATION.md), commit `5df9a95`), and the same sentence is in the Flagsmith experiment's hypothesis field.
- **The users are real.** Nobody here is simulated: every identity is an address that tried to log in to one of our servers.
- **Replay it with no key and nothing to install:** the website has no backend. Each page draws itself from one anonymised file, [`site/data/snapshot.json`](site/data/snapshot.json), so the final snapshot is also the replay. To run it on your machine: `python3 -m http.server 8765 --directory site`, then open http://localhost:8765.
- **The integrity gate runs before any result is read.** It prints PASS or FAIL for the sample ratio, unknown arm values, `came_back` in the log against the saved state, every event batch accepted by Flagsmith, and Flagsmith's numbers per arm against ours (details below).
- **Re-run the analysis yourself, also with nothing to install:** `python3 -m uninvited.report --snapshot site/data/snapshot.json` (standard library only) reads the same published file and prints the gate and every result: per arm, per /24 and per network operator, with the intervals. Only the check of the controller's private event log is skipped.
- **Result:** _pending until the last return window closes (about Sat 28 Nov, 3:05 PM IST)._ It is read from Flagsmith's results page and checked by our own calculation once the last window has closed. While the interval on the difference spans zero, the result is "can't call it", with the traffic that would settle it; that wording was fixed in advance.
- **Video:** _to come._
- **What a run costs:** about **$27 of AWS** (an estimate: 48 `t4g.nano` servers and one `t4g.micro` controller from Thursday to Saturday afternoon, stopped after the last window), and Flagsmith's free plan. Replaced with the bill after the run.

## The experiment

| | |
|---|---|
| Unit | One attacking IPv4 address, known to Flagsmith only as a keyed hash |
| Catch | Five failed SSH logins within ten minutes from one address on one server (fail2ban's defaults) |
| Arms (`ban_policy`, split 34 / 33 / 33) | `control` = `0`, no ban · `ban_10m` = `600`, 10 minutes · `ban_12h` = `43200`, 12 hours; every ban covers all servers, and a later catch bans again for the same length |
| Metric (`came_back`, lower is better) | The address reaches port 22 on any server 12h05m–24h05m after its first catch, after even the longest ban has ended |
| Enrolment | Thu 26 Nov 2:00 PM – Fri 27 Nov 3:00 PM IST (25 hours, at most 5,000 addresses); each address is evaluated once |
| Primary comparison | `ban_10m` against `control`; secondary `ban_12h` against `control` |
| Noise floor | `control` split in two by the identity's last hex digit, an A/A comparison |
| Robustness | The same comparison with one unit per /24 network, and per network operator |
| Stopping | No early stop: no decision before the last window closes |

**The fleet grew during enrolment, and each change is written below the line in the pre-registration with its reason.** It started with 12 servers in four AWS regions, became 24 at 2:08 PM and 48 in 13 regions by 5:14 PM, because far fewer attackers arrived than planned. The arms, the split, the catch rule, the metric, the dates and the analysis did not change.

## How Flagsmith is used

Without Flagsmith the servers don't know how long to ban: the flag is the ban policy for the whole fleet.

| Flagsmith part | What it does here |
|---|---|
| Multivariate flag `ban_policy` | Holds the ban length for every server: `0` (no ban), `600` (10 minutes), `43200` (12 hours). Flagsmith assigns each attacker an arm. |
| `get_experiment_flag` | Called once per newly caught attacker, with a keyed hash of its IP as the identity; records the exposure. |
| Event `came_back` | Sent with `track_event` the first time the attacker reaches port 22 again, 12h05m–24h05m after it was first caught. |
| Experiment | `came_back` as the primary metric, lower is better, with the pre-registered hypothesis. Its results page gives the win probability and the credible interval. |
| Flag `ban_enforce` | The kill switch, read every 30 seconds: off means no new enrolments and no new bans on any server. |
| Rollout | On the controller since Fri 27 Nov 3:17 PM IST. Once enrolment has closed, an attacker outside the experiment gets `ban_policy`'s value for everyone, read every 30 seconds along with the kill switch (environment flags, no identity, so no exposure). When the experiment ends, the winner is rolled out by setting that value in Flagsmith, and the next catch on any server gets it within 30 seconds. Attackers in the experiment keep their arm, so the rollout can't touch the measurement. |

## How it works

- **Servers** run stock OpenSSH on port 22 with a password prompt nobody can pass (every password is locked, root login is off). A small firewall table holds bans that expire by themselves and logs packets it drops.
- **One controller** holds every key. It follows each server's SSH log over SSH (a key that can only stream the log) and sends bans back (a key that can only run a ban script that accepts `ban <IPv4> <seconds>`). The servers hold no Flagsmith key.
- **A catch** is five failed logins within ten minutes from one IP on one server, as fail2ban counts them. Log lines are matched with patterns anchored so that an address typed into a username can't get someone else banned.
- **The website** is three static pages (Live, Results, Method) with no framework and no outside requests. `python -m uninvited.export` writes its one data file from the controller's files, and a new snapshot is committed at each check-in; the Pages workflow republishes it. More in [`site/README.md`](site/README.md).

| Where | What |
|---|---|
| `uninvited/sshlog.py` | Turns sshd's log lines into events about addresses |
| `uninvited/rules.py` | The pure decisions: what is a catch, how long an arm bans, the keyed identity, what counts as coming back |
| `uninvited/service.py` | Decides for every event: enrol, ban, or report `came_back` |
| `uninvited/controller.py` | Follows the servers' logs, sends bans, talks to Flagsmith |
| `uninvited/asn.py` | Network operator and country from an offline table, looked up once at enrolment |
| `uninvited/report.py` | The integrity gate and the pre-registered analysis |
| `uninvited/export.py` | The anonymised dataset the website reads |
| `fleet/` | Launcher with hard limits, cloud-init for servers and controller, the ban and log scripts, the firewall table, setup checks, the controller update script |
| `site/` | The website |
| `tests/` | 60 tests, run on every push by `.github/workflows/tests.yml` |

## Data

- **No address is kept.** The controller records each attacker as a keyed hash of its address (HMAC-SHA256, with a key made on the controller that never leaves it), a keyed hash of its /24, and its network operator's number (ASN) and country.
- The website and the export show only those. The export refuses to write anything that looks like an IPv4 address.
- **Usernames that attackers type are never stored or shown,** and sshd never logs passwords.
- Each server's own sshd log is the standard system log, which does name addresses. The controller reads it as a stream and keeps only the hashes; none of it is published.

## Limits

- **Small arms.** Far fewer attackers arrived than planned (about 2–3 catches an hour across 48 servers, against 25 planned), so the arms hold 17 to 25 attackers each and only a large difference could show. The pre-registration gives the smallest detectable drop for each sample size.
- **One unit is one address.** An attacker that comes back from a new address looks like one that stayed away. If bans push attackers to change address more often, bans look better than they are.
- **Attackers are not independent.** Botnets share target lists and networks: 20 of the 65 enrolled came from one network operator. That is why the comparison is rerun with one unit per /24 and per operator.
- **Cloud servers only,** with a password prompt nobody can pass. Attackers may treat home or company servers differently.
- **One day of enrolment and one 12–24-hour window.** Returns after a day are not measured.
- **Not tested:** escalating bans (fail2ban's `bantime.increment`) and the `recidive` jail, the obvious next arms.
- **Servers that joined later** could catch attackers only from the time they joined. Assignment is random, so this affects every arm alike.

## Setup

**You need:** an AWS account with the AWS CLI (profile `hackathon`, or change `PROFILE` in `fleet/launch.py`) and a cost budget with alerts that does not subtract credits (the launcher refuses to start anything without one); a Flagsmith account (the free Cloud plan works) with its managed warehouse turned on; Python 3.12+ and [uv](https://docs.astral.sh/uv/).

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
.venv/bin/python fleet/launch.py servers 12 --spend-ok --admin-port PORT   # spread over the regions in REGIONS (at most 48 servers)
.venv/bin/python fleet/hostkeys.py                                          # host keys from AWS console output
.venv/bin/python fleet/password_check.py HOST                               # each server: expect "PASS: every pair refused"
```
A new AWS account may allow only a few small instances per region until a quota increase; `REGIONS` lists 13 regions so servers can be spread out.

**5. Start the controller:** on the controller, write `/etc/uninvited/controller.env` from `fleet/controller.env.example`, the server list `/etc/uninvited/fleet.json` (`name`, `host`, `port` per server, from `data/fleet.json`), their host keys `/etc/uninvited/ssh/known_hosts` (from `data/known_hosts`) and the Flagsmith key file, then `sudo systemctl enable --now uninvited-controller`. To change its code later, commit and run `UNINVITED_ADMIN_PORT=PORT fleet/update-controller.sh CONTROLLER_HOST` (compares only), then the same with `--go`: it backs up the data, installs the committed code, restarts the service and reports what it logged.

**6. Start the experiment:** create the experiment on `ban_policy` in Flagsmith (rollout 100%, primary metric `came_back`), then turn `ban_enforce` on. Nobody is enrolled outside `UNINVITED_ENROL_FROM`–`UNINVITED_ENROL_UNTIL`.

**What you should see** in `/var/lib/uninvited/events.jsonl`: `controller_start`, one `stream_up` per server, `kill_switch` with `"enforcing": true`, and a `health` line every 5 minutes with events per server. When an attacker is caught inside the window: `enrolled` (hashed identity, arm, hashed /24, ASN, country), `banned`, one `ban_reply` per server, and 12–24 hours later perhaps `came_back`. In Flagsmith, the experiment's exposures rise with each enrolment.

**Check and analyse** (the integrity gate first, then the results):
```bash
cd /opt/uninvited && sudo python3 -m uninvited.report --data /var/lib/uninvited   # on the controller
python3 -m uninvited.report --data DIR --flagsmith flagsmith.json              # with Flagsmith's numbers per arm
python3 -m uninvited.report --snapshot site/data/snapshot.json                 # from the published dataset
```
The gate's output starts like this (from the controller on Fri 27 Nov, ~5:10 PM IST, after enrolment closed; 10 of 65 windows had closed):
```
INTEGRITY GATE
  [PASS] sample ratio (34/33/33): {'control': 25, 'ban_10m': 17, 'ban_12h': 23}, p = 0.493
  [PASS] no unknown arm values: 0 attackers with a value outside 0/600/43200
  [PASS] came_back: log matches state: 3 logged, 3 in state
  [PASS] every event batch accepted by Flagsmith: 68 batches, 0 not 2xx
  [----] Flagsmith comparison skipped (no --flagsmith file)
  [info] A/A noise floor (control, even vs odd identity): 1/3 vs 1/2, p = 0.71

GATE: PASS
```

**Update the website's data:**
```bash
python3 -m uninvited.export --data /var/lib/uninvited --out site/data/snapshot.json
```

**Tests:**
```bash
.venv/bin/python -m pytest
```

**Stop:** `.venv/bin/python fleet/launch.py stop` stops (does not delete) every instance; each one also powers itself off after 4 days.

## Before the hackathon / during the hackathon

- **Before 26 Nov:** the idea and plans, the art and the animated clips (see Credits), and a throwaway test of a free Flagsmith account with made-up identities (kept outside this repository; none of its data is in the experiment).
- **During (from 26 Nov 8:00 AM IST):** all the code in this repository, the website, the servers, and the experiment itself.

## Credits

- [OpenSSH](https://www.openssh.com/), [nftables](https://netfilter.org/projects/nftables/), the [Flagsmith Python SDK](https://github.com/Flagsmith/flagsmith-python-client).
- Network operator and country at enrolment: [iptoasn.com](https://iptoasn.com/)'s IP-to-ASN table (public domain, PDDL v1.0).
- The website's display type is Ubuntu Sans (Canonical), under the Ubuntu Font Licence ([`site/fonts/LICENCE.txt`](site/fonts/LICENCE.txt)).
- Art: the site's and the video's images were generated with **ChatGPT**, and the short animated clips with Google's **Gemini Omni**, from prompts written for this project.
- Video: narration in synthetic voices from **ElevenLabs**, reading a script written for this project; music "Immersed" by Kevin MacLeod ([incompetech.com](https://incompetech.com)), licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/); sound effects by DRAGON-STUDIO on Pixabay.

## Licence

MIT. See [LICENSE](LICENSE).

## AI tools used

This project was built with help from AI coding assistants.
