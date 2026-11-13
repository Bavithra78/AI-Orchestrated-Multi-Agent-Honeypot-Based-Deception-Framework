"""
agents/orchestrator.py  (Review-II)
Coordination bus: Detection -> Decision -> Deception -> Forensic, plus the
Response step (blocklist) that neutralises a source after it was deceived.
"""
import threading, time
from agents.detection_agent import DetectionAgent
from agents.decision_agent import DecisionAgent
from agents.honeydata_agent import HoneydataAgent
from agents.deception_agent import DeceptionAgent
from agents.forensic_agent import ForensicAgent
from config import AUTO_BLOCK, BLOCK_TTL_SECONDS, BLOCK_MIN_ENGAGEMENT


class Orchestrator:
    def __init__(self):
        self.detection_agent = DetectionAgent()
        self.decision_agent = DecisionAgent()
        self.honeydata_agent = HoneydataAgent()
        self.forensic_agent = ForensicAgent()
        self.deception_agent = DeceptionAgent(self.honeydata_agent, self.forensic_agent)
        self._redirected = set()
        self._hist = {}
        self._blocked = {}          # ip -> expiry timestamp
        self._lock = threading.Lock()

    # ---- response: blocklist -------------------------------------------
    def is_blocked(self, ip):
        with self._lock:
            exp = self._blocked.get(ip)
            if exp is None:
                return False
            if exp < time.time():
                del self._blocked[ip]
                return False
            return True

    def block(self, ip, session_id, reason):
        with self._lock:
            self._blocked[ip] = time.time() + BLOCK_TTL_SECONDS
        self.forensic_agent.log_event(session_id, "source_blocked", {"ip": ip, "ttl_s": BLOCK_TTL_SECONDS, "reason": reason})

    # ---- main pipeline --------------------------------------------------
    def process_message(self, session_id, message, real_fs_keys):
        if session_id in self._redirected:
            return None
        prior = list(self._hist.get(session_id, []))
        self._hist.setdefault(session_id, []).append(message)
        is_susp, reason, category = self.detection_agent.inspect(session_id, message)
        if not is_susp:
            return None
        self.forensic_agent.log_event(session_id, "alert", {"reason": reason, "message": message})
        decision = self.decision_agent.classify(category, reason, message)
        self.forensic_agent.log_event(session_id, "decision", decision)
        port = self.deception_agent.spawn_clone(session_id, decision["pillar"], decision["inject_honeydata"], prior)
        self.forensic_agent.log_event(session_id, "redirected", {"honeypot_port": port})
        self._redirected.add(session_id)
        self.detection_agent.reset(session_id)
        return {"decision": decision, "honeypot_port": port}

    def session_closed(self, session_id, ip):
        result = self.forensic_agent.close_session(session_id)
        if AUTO_BLOCK and result and result["score"] >= BLOCK_MIN_ENGAGEMENT:
            self.block(ip, session_id, f"engagement {result['score']} ({result['level']})")
        self._redirected.discard(session_id)
        self._hist.pop(session_id, None)
        return result
