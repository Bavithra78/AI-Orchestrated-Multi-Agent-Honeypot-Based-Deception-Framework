"""
agents/threat_rules.py
Detection rules written around how real intrusions behave, each tagged with the
MITRE ATT&CK technique it represents. First match wins.
Fields: (regex, technique id, tactic, pillar, label)
These are hand-written signatures (like IDS rules), not machine learning.
"""
import re

_SENS = (r"(\.env\b|id_rsa|id_ed25519|\.pem\b|\.kdbx|\.aws/credentials|\.git-credentials|\.git/config|\.pgpass|\.netrc|"
         r"wp-config|/etc/shadow|/etc/passwd|\bshadow\b|credentials?\b|secrets?\b|\.bash_history|"
         r"(config|database)\.(ya?ml|json|php|ini)|\.sql\b|\.bak\b|backup\S*\.(tar|tgz|gz|zip))")

RULES = [
    (r"base64\s+-d.*\|\s*(ba)?sh|/dev/tcp/|\bnc\b.*\s-e\s|\bbash\s+-i\b|(curl|wget)[^|]*\|\s*(ba)?sh|python3?\s+-c.*(socket|os\.system|pty)",
     "T1059", "Execution / reverse shell", "integrity", "command execution or reverse shell"),
    (r"(:\(\)\s*\{)|\bhping3?\b|slowloris|\bddos\b|\bflood\b|while\s+true",
     "T1498", "Impact / denial of service", "availability", "denial-of-service tooling"),
    (r"\b(shutdown|reboot|halt|poweroff)\b|systemctl\s+(stop|disable)\s+(nginx|mysql|sshd|apache|gunicorn)|kill\s+-9\s+-?1\b",
     "T1489", "Impact / service stop", "availability", "service stop or shutdown"),
    (r"\brm\s+-\w*r\w*\s+(/|\*|~)|dd\s+if=.*of=/dev/",
     "T1485", "Impact / data destruction", "integrity", "destructive command"),
    (r"authorized_keys|/etc/cron|\bcrontab\s+(-e|-r|-\s|\S+\.\S+)|\b(useradd|adduser|usermod)\b|systemctl\s+enable|>>?\s*\S*(\.bashrc|\.profile|rc\.local)",
     "T1098/T1053", "Persistence", "integrity", "persistence attempt"),
    (r"\bsudo\s+(-l|su|-i|bash|sh)\b|\bsu\s+-?\s*root|find\s.*-perm\s+-?(u=s|4000|2000)|chmod\s+(\+s|[0-7]?[4267][0-7]{3}|777)",
     "T1548", "Privilege escalation", "integrity", "privilege escalation"),
    (r"\b(wget|curl)\b.*(-O\s|-o\s).*(/tmp|/dev/shm)|\b(wget|curl)\s+(-\S+\s+)*https?://\d+\.\d+\.\d+\.\d+",
     "T1105", "Ingress tool transfer", "integrity", "download from raw IP / into /tmp"),
    (r"\bscp\b.*@|\brsync\b.*@|\bcurl\b.*(\s-T\s|--upload-file|\s-F\s|--data-binary|\s-d\s*@)|\bnc\b\s+\S+\s+\d+|\bftp\b|wget\b.*--post-file",
     "T1048", "Exfiltration", "confidentiality", "data exfiltration"),
    (r"\b(mysqldump|pg_dump|mongodump)\b|sqlite3\s.*\.dump|\bmysql\b.*-e\s.*select|\btar\b\s+\S*[cz]\S*.*(/var|/home|/etc|backup|www|\.sql)|\b(zip|7z)\b.*-r|\b(download|get)\s+\S+\.(csv|sql|db|xlsx|bak)",
     "T1005/T1560", "Collection", "confidentiality", "bulk data collection"),
    (r"\bselect\b.+\bfrom\b|\bunion\s+select\b|'\s*or\s*1=1",
     "T1190", "SQL access", "confidentiality", "SQL data query"),
    (r"\bdrop\s+table\b|\binsert\s+into\b|\bupdate\b.+\bset\b",
     "T1190", "SQL modification", "integrity", "SQL data modification"),
    (_SENS, "T1552/T1003", "Credential access", "confidentiality", "touches credential / secret file"),
    (r"\bgrep\b\s+-\w*r\w*\s.*(passw|secret|api.?key|token|credential)|\bfind\b.*-name.*(\.pem|id_rsa|\.env|credential|\.kdbx|\.key)|(env|printenv).*\|\s*grep.*(key|pass|secret|token)",
     "T1552.001", "Credential access", "confidentiality", "credential hunting"),
    (r"\b(ls|find|tree)\b.*(\.ssh|\.aws|/root|/var/backups)|/var/log/(auth\.log|secure)",
     "T1083", "Discovery of sensitive locations", "confidentiality", "sensitive directory discovery"),
]
COMPILED = [(re.compile(p, re.I), *rest) for p, *rest in RULES]


def match(command):
    for rx, tid, tactic, pillar, label in COMPILED:
        if rx.search(command):
            return {"technique": tid, "tactic": tactic, "pillar": pillar, "label": label}
    return None
