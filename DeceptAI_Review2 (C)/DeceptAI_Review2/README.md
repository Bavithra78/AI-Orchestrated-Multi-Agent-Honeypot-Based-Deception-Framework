# DeceptAI: multi-agent reactive deception (simulation)

Pure Python 3, no pip installs. Simulates the flow of the base paper (Beltran-Lopez et al.,
*Computer Networks* 281, 2026): detect a suspicious session, spawn an on-demand honeypot clone,
silently redirect the attacker, serve fake data, record forensics. Our additions: agent split,
ATT&CK-tagged detection rules, a stateful fake shell, engagement score, auto-block, scale-tested design.

## Real-world example (main demo)
`scenario_stolen_credentials.py` plays a real intrusion pattern: the attacker logs in with a valid
stolen password (no second factor), then does recon -> credential hunting -> uses the stolen DB
password -> database dump -> scp exfiltration -> plants an SSH key.
Why this pattern: stolen credentials were the top initial-access vector in Verizon DBIR 2025 (22% of breaches)
and the 2021 Colonial Pipeline attackers entered through a legacy VPN account protected by one password.
It is the same pattern on a made-up server, NOT a replay of that incident.
What DeceptAI does: recon is answered by the real server; `cat .env` (ATT&CK T1552 credential access)
triggers detection -> clone with fake secrets (HP-xxxx-FAKE-*) -> the attacker keeps going, uses the fake
password, "exfiltrates" a fake dump -> everything is logged, scored (engagement) and optionally blocked.
DeceptAI does NOT stop the stolen-password login itself; it limits what the intruder reaches afterwards.

## Run (4 terminals, inside the project folder)
1. `python victim_server.py`                  real server :9000
2. `python sdn_controller.py`                 public port :8000 (agents inside)
3. `python dashboard/dashboard_server.py`     open http://127.0.0.1:8080
4. `python scenario_stolen_credentials.py`    (`--fast` skips pauses). `attacker_simulator.py` is the old 8-command toy demo.
Auto-block (Linux): `DECEPTAI_AUTO_BLOCK=1 DECEPTAI_BLOCK_MIN=20 python sdn_controller.py`

## Honest scope
* SDN data plane (Mininet/Ryu/OpenFlow, TCP sequence-number manipulation) is replaced by an application-layer
  transparent TCP proxy (`sdn_controller.py`). Same functional steps, different mechanism.
* Detection = hand-written regex rules mapped to MITRE ATT&CK (`agents/threat_rules.py`) + a message-count rule. No ML, no dataset.
* Honeydata = templates, no LLM. Everything runs on localhost against an emulated shell (`agents/shell_emulator.py`), not real SSH.
* State carried into the clone: `cd` and file changes made before the redirect (history replay). Not carried: anything else.
* An experienced attacker could fingerprint an emulated shell (timing, odd outputs); no claim otherwise.

## Benchmark  (`python benchmark.py`, about 2 min; `--quick` 20 s) -> results.json
Saved runs (Linux container, 2 vCPU, Python 3.13) are in `benchmark_results/`:
review1_baseline vs review2. Re-run on your own laptop and quote YOUR numbers.
* Scale: Review-I build fails past ~100 clones (fixed 100-port range, leaked sockets); Review-II ran 400 concurrent sessions at 100% success.
* Detection, corpus 1 (50+50 commands, rules were written with this corpus in view -> optimistic): P 1.00 / R 1.00.
* Detection, held-out corpus 2 (25+25, written after rules were frozen): Review-II P 1.00 / R 0.72; Review-I keyword rules P 0.65 / R 0.44.
  Misses: kube config, aws s3 cp, crontab via pipe, history grep, gcloud token, /proc environ, sqlmap.
* Base paper's numbers (1.6 ms latency deviation, KS-test, etc.) are the authors', not ours.

## Layout
agents/ detection, threat_rules, decision, honeydata, deception, shell_emulator, forensic, engagement, orchestrator.
config.py settings. logs/ forensic_report.json + events.jsonl.
