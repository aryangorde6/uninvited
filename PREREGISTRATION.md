# Pre-registration: does fail2ban's 10-minute ban stop attackers coming back?

Written before the experiment starts, and committed so its timestamp proves that. Nothing here changes after the start; any later change is added below the line with its own date and reason.

## Hypothesis (also in Flagsmith's hypothesis field)

> Banning an attacker for fail2ban's default 10 minutes does not lower the share who come back 12–24 hours after their first catch, compared with no ban, for attackers first caught between Thu 26 Nov 2026 2:00 PM and Fri 27 Nov 2026 3:00 PM IST.

## Design

- **Unit:** one attacking IPv4 address, identified to Flagsmith only by a keyed hash (`ip-` + 20 hex characters of HMAC-SHA256).
- **Catch:** five failed SSH logins within ten minutes from one address on one server (fail2ban's defaults). One login attempt is one failure.
- **Arms**, assigned by Flagsmith through the multivariate flag `ban_policy`, about one third each:
  - `control`: value `0`, no ban;
  - `ban_10m`: value `600`, banned for 10 minutes on all 12 servers;
  - `ban_12h`: value `43200`, banned for 12 hours on all 12 servers.
  - Each later catch of the same address bans it again for the same length, as fail2ban does.
- **Enrolment:** at an address's first catch while the kill switch `ban_enforce` is on, from **Thu 26 Nov 2026 2:00 PM IST** until **Fri 27 Nov 2026 3:00 PM IST** (25 hours), or until 5,000 addresses are enrolled, whichever comes first. Each identity is evaluated once.
- **Metric (`came_back`, occurrence, lower is better):** the address reaches port 22 on any of the 12 servers between 12h05m and 24h05m after its first catch. Reaching port 22 means any sshd line naming the address, or a packet to port 22 dropped by a ban (the firewall logs at most one per minute per banned address). The window opens after the longest ban (12 h) has ended. The last window closes about Sat 28 Nov 2026 3:05 PM IST.
- **Fleet:** 12 servers (AWS t4g.nano, Ubuntu 24.04, OpenSSH 9.6p1, which has no `PerSourcePenalties`), three each in us-east-1, eu-central-1, ap-southeast-1 and us-west-2, launched 26 Nov between 12:43 and 12:53 PM IST. Port 22 offers a password prompt that cannot succeed (every account is locked). No other blocking runs on them.

## Predictions

- `ban_10m` about equal to `control` (the hypothesis).
- `ban_12h` lower than `control`, if anything.

## Analysis, fixed now

- **Primary comparison:** `ban_10m` against `control` on `came_back`, read from Flagsmith's results page: the win probability and the credible interval on the difference. While the interval spans zero, the result is reported as "can't call it", with the traffic that would settle it.
- **Secondary:** `ban_12h` against `control`.
- **Noise floor:** `control` split in two by the last hex digit of the identity (even against odd), an A/A comparison computed from the controller's log.
- **Integrity gate, run before reading any result:** a sample-ratio test on the three arms; Flagsmith's exposures per arm against the controller's enrolments; `came_back` events against the controller's log.
- **Cross-check:** an independent Beta-binomial calculation from the controller's log.
- **Robustness:** the same comparison with one unit per /24 network, and per network operator.
- **No early stop.** Results may be watched but no decision is taken before the last window closes.

## Smallest detectable drop

No pilot ran, so the base rate of returns is unknown. Approximate smallest absolute drop in the return rate detectable with 80% power at the 5% level, per arm:

| Base return rate | 100 per arm | 200 per arm | 400 per arm |
|---|---|---|---|
| 15% | 14 points | 10 points | 7 points |
| 25% | 17 points | 12 points | 9 points |
| 40% | 19 points | 14 points | 10 points |

## Wording for a tie

"Over N attackers per arm, a 10-minute ban did not measurably change how many came back 12–24 hours later (difference X points, interval A to B). A difference smaller than about D points can't be ruled out."

## Before the experiment

A throwaway test on 25–26 Nov with made-up identities (not in this repository) showed that Flagsmith counts exposures, immediate conversions and conversions sent 14.3 hours late exactly. No data from that test enters this experiment.

---

_Changes after the start, if any, go here with their date and reason._

- **Thu 26 Nov 2026, ~2:08 PM IST: 24 servers instead of 12.** Attack volume was near zero: in the fleet's first ~75 minutes, 11 of the 12 servers saw 0–2 outside addresses each, and only one address made five or more attempts. The plan allowed new servers to join if volume was low (the arms can't change). So 12 more servers from the same template, three more in each of the four regions, were launched between 1:52 and 1:58 PM, passed the same checks (accounts locked, root login off, common passwords refused, firewall table loaded, ban link tested), and joined the controller at about 2:08 PM. The arms, the split, the catch rule, the metric window, the enrolment dates and the analysis are unchanged; a catch or a return now counts on any of the 24 servers, and a ban applies on all 24. The controller was restarted to add them; no attacker had been enrolled before the restart.

- **Thu 26 Nov 2026, ~5:00–5:15 PM IST: 48 servers instead of 24.** Volume was still low: 10 attackers enrolled between 2:00 and 5:00 PM (about 3 an hour), on 6 of the 24 servers. The servers' own logs since 2:00 PM showed that every address that tried passwords five times was caught, so the limit is how many attackers find the servers, not the catch rule. So 24 more servers from the same template were added: 7 in the same four regions (launched 3:24–3:29 PM, joined ~5:00 PM), then 17 more, 2 in each of nine more regions (1 in São Paulo), because AWS allows only 8 small servers in each of the first four regions and 2 in each new one (launched ~5:05 PM, joined ~5:14 PM). All 24 passed the same checks before joining (setup finished, accounts locked, root login off, empty passwords refused, 20 common passwords refused, firewall table and drop log loaded, ban link and log link tested). The controller was restarted twice to add them; it kept its saved state and each server's log position, and the 10 enrolled attackers kept their arms. The two 12-hour bans active at the time were copied to the new servers with their remaining time, so every ban still covers the whole fleet. The admin's new laptop address was added to the never-enrol and never-ban lists (the old one stays). The arms, the split, the catch rule, the metric window, the enrolment dates (still ending Fri 27 Nov 3:00 PM) and the analysis are unchanged. A server that joined later can only catch attackers from the time it joined; a return counts on any of the 48 servers.

- **Thu 26 Nov 2026, ~10:54 PM IST: the rollout path (code, written after the start; not yet on the controller).** Until now an attacker first caught after enrolment closes was only logged. With this change, once enrolment has closed (Fri 27 Nov 3:00 PM), an attacker outside the experiment gets the value `ban_policy` holds for everyone, which the controller reads every 30 seconds with the kill switch; that is how the winner is rolled out with the same flag after the experiment ends. Attackers enrolled in the experiment keep their arm, every `came_back` window is measured as before, and nothing is sent to Flagsmith for these attackers, so the arms, the split, the metric and the analysis are unchanged. The controller is to be updated with it after enrolment closes, so no enrolment happens on the new code; the time will be added here.

- **Fri 27 Nov 2026, 3:17 PM IST: the rollout path is on the controller.** Enrolment closed at 3:00 PM with 65 attackers (`control` 25, `ban_10m` 17, `ban_12h` 23). At 3:17:46 PM the controller was updated to commit `5cb6d3c` (it includes the rollout path above and `1a49891`, which stops the controller with SIGINT so buffered Flagsmith events are sent first) and restarted. After the restart it reported a clean stop, all 48 log streams up, the kill switch on and `ban_policy` = 0 for everyone outside the experiment, so nothing changes for anyone until the flag is changed after the experiment ends. No attacker was enrolled on the new code. Found while preparing the update: Ubuntu's automatic updates restarted the controller twice on Fri 27 Nov at about 12:02 PM IST (during enrolment), with the old stop signal. Its event log shows every event before that was already sent and accepted (the last one at about 11:40 AM), and the saved state and log positions carried over, so nothing was lost; the arms, the split, the metric and the analysis are unchanged.
