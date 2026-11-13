"""
victim_server.py
Simulates the real, legitimate asset (e.g. an SSH-like shell service)
that the attacker is trying to compromise. This is the "Victim" in the
base paper's Fig. 3 topology.

Run standalone for testing:
    python3 victim_server.py
"""
import socket
import threading
from config import HOST, VICTIM_PORT
from agents.shell_emulator import ShellEmulator, base_files

# A tiny fake shell filesystem for the REAL victim (never shown to a
# redirected/deceived attacker once cloning kicks in).
REAL_FS = {
    "whoami": "victim-prod-01",
    "pwd": "/home/appadmin",
    "ls": "app.py  config.yaml  requirements.txt  logs/",
    "cat config.yaml": "db_host: prod-db-internal.local\napi_key: <REDACTED-REAL-SECRET>\n",
    "id": "uid=1000(appadmin) gid=1000(appadmin) groups=1000(appadmin)",
}


def handle_client(conn, addr, label="VICTIM"):
    shell = ShellEmulator(base_files(real=True))
    conn.sendall(f"Welcome to prod-server (SSH) -- {label}\n$ ".encode())
    while True:
        try:
            data = conn.recv(1024)
        except (ConnectionResetError, OSError):
            break
        if not data:
            break
        cmd = data.decode(errors="ignore").strip()
        if cmd in ("exit", "quit"):
            conn.sendall(b"logout\n")
            break
        response = shell.run(cmd)
        conn.sendall((response + "\n$ " if response else "$ ").encode())
    conn.close()


def serve(port=VICTIM_PORT, label="VICTIM"):
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind((HOST, port))
    srv.listen(256)
    print(f"[{label}] listening on {HOST}:{port}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr, label), daemon=True).start()


if __name__ == "__main__":
    serve()
