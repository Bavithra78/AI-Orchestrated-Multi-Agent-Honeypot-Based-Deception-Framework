"""
sdn_controller.py
Controller Proxy -- the entry point of the framework.

Acts as the SDN Controller's public-facing port (see config.py's note on
scope: this is an application-layer transparent proxy standing in for
real OpenFlow flow-mod redirection). For every attacker connection it:

  1. Opens a matching backend connection to the real VICTIM.
  2. Relays each attacker message to the Orchestrator for inspection.
  3. If the Orchestrator flags the message, it transparently swaps the
     backend connection to a freshly-cloned Honeypot (with LLM-style
     honeydata already injected) -- the attacker's own socket never
     changes, so from their point of view nothing happened, exactly
     matching the base paper's "Restore Connection / Messages Exchange"
     step (Fig. 2, steps 4-5).
  4. Every command sent after redirection is captured by the Forensic
     Agent for threat-intelligence reporting.

Run:
    python3 victim_server.py        # terminal 1
    python3 sdn_controller.py       # terminal 2
    python3 attacker_simulator.py   # terminal 3 (or a real telnet/nc client)
"""
import socket
import threading
import uuid

from config import HOST, CONTROLLER_LISTEN_PORT, VICTIM_PORT, LISTEN_BACKLOG
from agents.orchestrator import Orchestrator

REAL_FS_KEYS = ["whoami", "pwd", "ls", "cat config.yaml", "id"]


class ControllerProxy:
    def __init__(self):
        self.orchestrator = Orchestrator()

    def handle_attacker(self, attacker_conn, addr):
        session_id = str(uuid.uuid4())[:8]
        if self.orchestrator.is_blocked(addr[0]):
            print(f"[CONTROLLER] Refused connection from blocked source {addr[0]}")
            attacker_conn.close()
            return
        print(f"[CONTROLLER] New session {session_id} from {addr}")
        attacker_conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            backend.connect((HOST, VICTIM_PORT))
        except OSError:
            attacker_conn.close()
            return
        redirected = False

        # Relay the server's welcome banner first
        banner = backend.recv(1024)
        attacker_conn.sendall(banner)

        while True:
            try:
                data = attacker_conn.recv(1024)
            except OSError:
                break
            if not data:
                break
            message = data.decode(errors="ignore").strip()

            if not redirected:
                result = self.orchestrator.process_message(session_id, message, REAL_FS_KEYS)
                if result is not None:
                    # --- Stealthy redirection happens here ---
                    print(f"[CONTROLLER] Session {session_id}: suspicious activity detected "
                          f"({result['decision']['reason']}) -> redirecting to honeypot "
                          f"on port {result['honeypot_port']} "
                          f"[honeydata={'yes' if result['decision']['inject_honeydata'] else 'no'}]")
                    try:
                        backend.close()
                    except OSError:
                        pass
                    backend = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    backend.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                    try:
                        backend.connect((HOST, result["honeypot_port"]))
                        backend.recv(1024)  # discard honeypot's own welcome banner
                    except OSError:
                        break
                    redirected = True
            # (no extra logging needed here once redirected -- the honeypot's
            # own handler already logs every attacker_command it receives)

            try:
                backend.sendall(data)
                response = backend.recv(4096)
            except OSError:
                break
            if not response:
                break
            attacker_conn.sendall(response)

            if message in ("exit", "quit"):
                break

        attacker_conn.close()
        try:
            backend.close()
        except OSError:
            pass
        eng = self.orchestrator.session_closed(session_id, addr[0])
        summary = self.orchestrator.forensic_agent.summary(session_id)
        print(f"[CONTROLLER] Session {session_id} closed. Summary: {summary}"
              + (f" | engagement={eng['score']} ({eng['level']})" if eng else ""))

    def serve(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, CONTROLLER_LISTEN_PORT))
        srv.listen(LISTEN_BACKLOG)
        print(f"[CONTROLLER] SDN Controller (proxy) listening on {HOST}:{CONTROLLER_LISTEN_PORT}")
        print(f"[CONTROLLER] Forwarding benign traffic to Victim at {HOST}:{VICTIM_PORT}")
        while True:
            conn, addr = srv.accept()
            threading.Thread(target=self.handle_attacker, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    ControllerProxy().serve()
