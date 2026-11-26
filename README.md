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

_Being written: environment variables, the run command and what you should see._

```bash
uv venv && uv pip install -e . pytest
.venv/bin/python -m pytest
```

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
