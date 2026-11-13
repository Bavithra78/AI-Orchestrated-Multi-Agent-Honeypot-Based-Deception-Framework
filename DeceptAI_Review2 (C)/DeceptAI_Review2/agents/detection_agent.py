"""Detection Agent -- ATT&CK-tagged signature rules + a message-count anomaly rule."""
from agents.threat_rules import match
from config import SUSPICIOUS_MESSAGE_COUNT_THRESHOLD


class DetectionAgent:
    def __init__(self):
        self._message_counts = {}

    def inspect(self, session_id, message):
        self._message_counts[session_id] = self._message_counts.get(session_id, 0) + 1
        count = self._message_counts[session_id]
        m = match(message)
        if m:
            return True, f"{m['technique']} {m['tactic']}: {m['label']}", m["pillar"]
        if count >= SUSPICIOUS_MESSAGE_COUNT_THRESHOLD:
            return True, f"message count threshold exceeded ({count} messages in session)", "anomaly"
        return False, None, None

    def reset(self, session_id):
        self._message_counts.pop(session_id, None)
