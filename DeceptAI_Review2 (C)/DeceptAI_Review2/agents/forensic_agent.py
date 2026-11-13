"""
agents/forensic_agent.py  (Review-II)
Per-session threat-intelligence timeline.

Changes vs Review-I:
  * thread-safe (one lock) -- Review-I mutated a dict while other threads dumped it
  * report is flushed by a background thread every FORENSIC_FLUSH_INTERVAL
    (Review-I rewrote the whole file after EVERY event: O(n^2) I/O)
  * atomic write (tmp file + os.replace) so the dashboard never reads half a file
  * append-only events.jsonl audit trail for durability
  * engagement score computed when a session closes
"""
import json, os, threading, time
from config import LOG_DIR, FORENSIC_REPORT_PATH, FORENSIC_FLUSH_INTERVAL, FORENSIC_EVENT_LOG
from agents import engagement


class ForensicAgent:
    def __init__(self):
        os.makedirs(LOG_DIR, exist_ok=True)
        self._sessions = {}
        self._lock = threading.Lock()
        self._dirty = True
        self._stop = False
        self._jsonl = open(FORENSIC_EVENT_LOG, "a", buffering=1)
        self._flush()
        threading.Thread(target=self._flusher, daemon=True).start()

    def log_event(self, session_id, event_type, details=None):
        entry = {"event": event_type, "timestamp": round(time.time(), 3), "details": details or {}}
        with self._lock:
            self._sessions.setdefault(session_id, []).append(entry)
            self._dirty = True
            self._jsonl.write(json.dumps({"session": session_id, **entry}) + "\n")

    def close_session(self, session_id):
        """Called by the controller when the attacker disconnects."""
        with self._lock:
            events = list(self._sessions.get(session_id, []))
        redirected = [e for e in events if e["event"] == "redirected"]
        if not redirected:
            return None
        cmds = [e for e in events if e["event"] == "attacker_command"]
        dwell = (cmds[-1]["timestamp"] - redirected[0]["timestamp"]) if cmds else 0.0
        result = engagement.score([e["details"].get("command", "") for e in cmds], dwell)
        self.log_event(session_id, "engagement_score", result)
        return result

    def summary(self, session_id):
        with self._lock:
            events = list(self._sessions.get(session_id, []))
        return {"session_id": session_id, "num_events": len(events), "timeline": [e["event"] for e in events]}

    def snapshot(self):
        with self._lock:
            return {k: list(v) for k, v in self._sessions.items()}

    def flush_now(self):
        self._dirty = True
        self._flush()

    def _flusher(self):
        while not self._stop:
            time.sleep(FORENSIC_FLUSH_INTERVAL)
            if self._dirty:
                self._flush()

    def _flush(self):
        with self._lock:
            data = {k: list(v) for k, v in self._sessions.items()}
            self._dirty = False
        tmp = FORENSIC_REPORT_PATH + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, FORENSIC_REPORT_PATH)
        except OSError:
            pass
