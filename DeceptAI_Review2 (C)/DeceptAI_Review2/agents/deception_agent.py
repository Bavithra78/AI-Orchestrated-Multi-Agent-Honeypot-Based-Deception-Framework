"""
agents/deception_agent.py  (Review-II)
Spawns an on-demand honeypot clone for ONE attacker session.

Changes vs Review-I:
  * OS-assigned (ephemeral) port instead of a 100-port range -> no collisions
    when more than 100 clones are alive
  * the clone's listener closes after the single expected connection, and
    self-destructs after HONEYPOT_IDLE_TIMEOUT if nobody connects (Review-I
    leaked one listening socket + one thread per session forever)
  * larger listen backlog, TCP_NODELAY
"""
import socket, threading
from agents.shell_emulator import ShellEmulator
from config import HOST, HONEYPOT_PORT_RANGE, USE_EPHEMERAL_HONEYPOT_PORTS, HONEYPOT_IDLE_TIMEOUT



class DeceptionAgent:
    def __init__(self, honeydata_agent, forensic_agent):
        self.honeydata_agent = honeydata_agent
        self.forensic_agent = forensic_agent
        self._next_port = HONEYPOT_PORT_RANGE[0]
        self._lock = threading.Lock()
        self.active_clones = 0

    def _bind(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if USE_EPHEMERAL_HONEYPOT_PORTS:
            srv.bind((HOST, 0))
        else:
            with self._lock:
                port = self._next_port
                self._next_port = port + 1 if port < HONEYPOT_PORT_RANGE[1] else HONEYPOT_PORT_RANGE[0]
            srv.bind((HOST, port))
        srv.listen(8)
        return srv, srv.getsockname()[1]

    def spawn_clone(self, session_id, pillar, inject_honeydata, history=None):
        srv, port = self._bind()
        from agents.shell_emulator import base_files
        files = self.honeydata_agent.generate(pillar) if inject_honeydata else base_files(real=True)
        shell = ShellEmulator(files)
        shell.replay(history or [])     # carry over cd / file changes made before the redirect
        with self._lock:
            self.active_clones += 1

        def serve_once():
            srv.settimeout(HONEYPOT_IDLE_TIMEOUT)
            try:
                conn, _ = srv.accept()
            except (socket.timeout, OSError):
                srv.close()
                with self._lock:
                    self.active_clones -= 1
                return
            srv.close()  # single-use clone: no further connections accepted
            conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            conn.sendall(f"Welcome to prod-server (SSH) -- HONEYPOT[{session_id}]\n$ ".encode())
            while True:
                try:
                    data = conn.recv(1024)
                except OSError:
                    break
                if not data:
                    break
                cmd = data.decode(errors="ignore").strip()
                if cmd in ("exit", "quit"):
                    try:
                        conn.sendall(b"logout\n")
                    except OSError:
                        pass
                    break
                self.forensic_agent.log_event(session_id, "attacker_command", {"command": cmd})
                try:
                    out = shell.run(cmd)
                    conn.sendall((out + "\n$ " if out else "$ ").encode())
                except OSError:
                    break
            conn.close()
            with self._lock:
                self.active_clones -= 1

        threading.Thread(target=serve_once, daemon=True).start()
        self.forensic_agent.log_event(session_id, "honeypot_spawned",
                                      {"port": port, "pillar": pillar, "honeydata": inject_honeydata})
        return port
