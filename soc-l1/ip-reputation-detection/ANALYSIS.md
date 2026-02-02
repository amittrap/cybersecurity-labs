## SOC IP Reputation Analysis

### Objective
Enhance brute-force detection by validating attacker IPs against a known
blacklist to increase alert confidence.

### Detection Logic
- IPs flagged during brute-force detection are checked against a blacklist
- Blacklisted IPs are escalated with higher severity

### SOC Value
Combining detection with threat intelligence reduces false positives and helps
prioritize analyst response.
