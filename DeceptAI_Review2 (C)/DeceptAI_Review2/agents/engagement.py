"""
agents/engagement.py
Attacker Engagement Score (0-100): a simple, transparent heuristic for how
deeply an attacker worked inside the decoy.

    score = 100 * ( w_c * min(commands / cap_c, 1)
                  + w_d * min(dwell_s  / cap_d, 1)
                  + w_s * min(sensitive/ cap_s, 1) )

commands  : attacker commands executed on the honeypot
dwell_s   : seconds between redirection and the last captured command
sensitive : commands that touched sensitive-looking targets (config, secret,
            passwd, shadow, key, .env, backup, ...)
Levels: <20 Low, 20-59 Medium, >=60 High.
"""
from config import ENGAGEMENT_WEIGHTS as W, ENGAGEMENT_CAPS as C

SENSITIVE_HINTS = ("config", "secret", "passwd", "shadow", "key", ".env", "backup", "id_rsa", "database", "token", "passw", "dump", "authorized_keys", ".pem", ".aws", "scp", "tar ")


def score(commands, dwell_seconds):
    n = len(commands)
    sens = sum(1 for c in commands if any(h in c.lower() for h in SENSITIVE_HINTS))
    s = 100 * (W["commands"] * min(n / C["commands"], 1)
               + W["dwell"] * min(dwell_seconds / C["dwell_seconds"], 1)
               + W["sensitive"] * min(sens / C["sensitive"], 1))
    s = round(s, 1)
    level = "Low" if s < 20 else ("Medium" if s < 60 else "High")
    return {"score": s, "level": level, "commands": n, "dwell_seconds": round(dwell_seconds, 2), "sensitive_touches": sens}
