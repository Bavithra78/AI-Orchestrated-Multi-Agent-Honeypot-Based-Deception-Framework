"""
attacker_simulator.py
Simulates an attacker connecting to the Controller and issuing a mix of
normal and suspicious commands, so you can watch stealthy redirection
happen live. Prints everything the "attacker" sees -- notice the
attacker never sees any interruption, exactly like the base paper's
undetectability claim (Experiment 1 / KS-test results).

Run (after victim_server.py and sdn_controller.py are already running):
    python3 attacker_simulator.py
"""
import socket
import time

from config import HOST, CONTROLLER_LISTEN_PORT

# A realistic attacker session: a few normal-looking probes, then a
# command that trips the Detection Agent's sensitive-command signature.
COMMANDS = [
    "whoami",
    "pwd",
    "ls",
    "id",
    "cat config.yaml",   # <-- flagged as a confidentiality-sensitive command
    "cat secret.txt",    # now talking to the honeypot without knowing it
    "cat access.log",
    "exit",
]


def run():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, CONTROLLER_LISTEN_PORT))
    print(s.recv(1024).decode(), end="")

    for cmd in COMMANDS:
        time.sleep(0.6)
        print(f"\n>>> attacker sends: {cmd}")
        s.sendall(cmd.encode())
        reply = s.recv(4096).decode(errors="ignore")
        print(reply, end="")

    s.close()
    print("\n\n[ATTACKER] Session ended. From my side, this looked like one continuous session with a single server.")


if __name__ == "__main__":
    run()
