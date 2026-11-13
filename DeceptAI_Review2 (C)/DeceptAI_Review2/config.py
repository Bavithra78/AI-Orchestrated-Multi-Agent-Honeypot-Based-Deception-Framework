"""
config.py
Shared configuration for the AI-Orchestrated Multi-Agent Honeypot-Based
Deception Framework (Review-II build: scalable, with engagement scoring and auto-block).

This is a pure-Python, dependency-free simulation of the base paper's
architecture (SDN Controller + IDS + on-demand honeypot cloning + LLM
honeydata) extended with the proposed multi-agent coordination layer.

NOTE ON SCOPE:
Real Mininet + Ryu + OpenFlow require a Linux host with root privileges
and kernel network-namespace support, which is not available on every
student laptop. To keep this "easy to run" on any machine with plain
Python 3, the SDN data-plane (OpenvSwitch + OpenFlow redirection with
TCP sequence-number offsetting) is REPLACED with an application-layer
transparent TCP proxy that performs the same functional steps described
in the base paper's Algorithm 1: detect -> clone -> redirect -> restore.
This keeps the attacker-facing socket identical across the redirection,
so from the Attacker's point of view the session is never interrupted --
the same behavioural guarantee the base paper achieves at the transport
layer via sequence-number manipulation. When you get real Mininet/Ryu
access, `sdn_controller.py`'s ControllerProxy class is the piece to swap
for actual OpenFlow flow-mod rules -- everything above it (the agents)
stays the same.
"""

HOST = "127.0.0.1"

VICTIM_PORT = 9000          # Real / legitimate asset
CONTROLLER_LISTEN_PORT = 8000  # Attacker connects here (acts as the SDN Controller's public-facing port)
HONEYPOT_PORT_RANGE = (9500, 9600)  # Ports used for on-demand honeypot clones

# Detection thresholds (mirrors the base paper's Snort "MIGRATE" rule,
# which triggers on the 100th packet in a flow). Kept small here so a
# demo run shows redirection within a few seconds.
SUSPICIOUS_MESSAGE_COUNT_THRESHOLD = 12

# Keyword-based signatures (simple stand-in for Snort rules)
CONFIDENTIALITY_INTEGRITY_KEYWORDS = [
    "cat ", "type ", "get ", "download", "cp ", "scp", "wget", "curl",
    "passwd", "shadow", "config", ".env", "secret", "id_rsa", "database",
    "select ", "drop table", "insert into", "update ", "chmod", "sudo",
]
AVAILABILITY_KEYWORDS = [
    "flood", "ddos", "dos ", "loop", ":(){ :|:& };:", "hping", "slowloris",
]

LOG_DIR = "logs"
FORENSIC_REPORT_PATH = "logs/forensic_report.json"


# ---------------- Review-II scalability / response additions ----------------
USE_EPHEMERAL_HONEYPOT_PORTS = True   # OS-assigned ports: no 100-clone ceiling (v1 used HONEYPOT_PORT_RANGE)
HONEYPOT_IDLE_TIMEOUT = 30            # seconds a clone waits for its attacker before self-destructing
LISTEN_BACKLOG = 256                  # v1 used 5
FORENSIC_FLUSH_INTERVAL = 0.5         # seconds; report is written in the background, not per event
FORENSIC_EVENT_LOG = "logs/events.jsonl"   # append-only audit trail (one JSON object per line)

# Neutralisation: block a source after it was deceived and went deep into the decoy
import os
AUTO_BLOCK = os.environ.get("DECEPTAI_AUTO_BLOCK", "0") == "1"   # True: refuse repeat connections from flagged sources
BLOCK_TTL_SECONDS = 300
BLOCK_MIN_ENGAGEMENT = int(os.environ.get("DECEPTAI_BLOCK_MIN", "40"))   # engagement score (0-100) at which a source is blocked

# Engagement score weights (sum to 1.0) -- see agents/engagement.py
ENGAGEMENT_WEIGHTS = {"commands": 0.4, "dwell": 0.3, "sensitive": 0.3}
ENGAGEMENT_CAPS = {"commands": 10, "dwell_seconds": 60, "sensitive": 3}
