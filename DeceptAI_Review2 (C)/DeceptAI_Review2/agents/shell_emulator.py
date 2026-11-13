"""
agents/shell_emulator.py
A small STATEFUL fake Linux shell (virtual filesystem, cwd, redirections,
pipes into grep/head/tail) used by BOTH the real victim and the honeypot
clones, so the attacker sees the same kind of environment before and after
the redirect. Only the secrets differ (real vs honeydata).

Not a full shell: it understands the commands a real intruder uses during
recon, credential hunting, collection, exfiltration and persistence.
"""
import fnmatch, posixpath, re, shlex

HOME = "/home/appadmin"
HOST = "prod-app-01"
USER = "appadmin"

_PASSWD = ("root:x:0:0:root:/root:/bin/bash\nwww-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
           "mysql:x:114:121:MySQL Server:/nonexistent:/bin/false\nappadmin:x:1000:1000:App Admin:/home/appadmin:/bin/bash\n")


def base_files(real=True, token="0000"):
    """Filesystem content. real=True -> 'production' secrets (placeholders in this
    simulation); real=False -> honeydata that is fake but looks the same."""
    if real:
        db_pw, aws_id, aws_sec = "<REAL-DB-PASSWORD>", "<REAL-AWS-KEY-ID>", "<REAL-AWS-SECRET>"
        db_host, api = "prod-db-internal.local", "<REDACTED-REAL-SECRET>"
    else:
        db_pw, aws_id, aws_sec = f"HP-{token}-FAKE-PASS", f"AKIAHPFAKE{token}", f"HP-{token}-FAKE-SECRET"
        db_host, api = "honey-db-internal.local", f"HP-{token}-FAKE-KEY"
    env = (f"APP_ENV=production\nDB_HOST={db_host}\nDB_USER=appuser\nDB_PASSWORD={db_pw}\n"
           f"AWS_ACCESS_KEY_ID={aws_id}\nAWS_SECRET_ACCESS_KEY={aws_sec}\n")
    return {
        f"{HOME}/config.yaml": f"db_host: {db_host}\napi_key: {api}\nadmin_email: admin@corp-internal.example\n",
        f"{HOME}/secret.txt": f"Internal memo (DRAFT) -- do not distribute\nref: HP-{token}\nQ3 budget figures pending review.\n",
        f"{HOME}/access.log": "10.0.0.14 - - [admin login] 200\n10.0.0.22 - - [file download] 200\n",
        f"{HOME}/app.py": "from flask import Flask\napp = Flask(__name__)\n",
        f"{HOME}/requirements.txt": "flask==3.0.0\nmysqlclient==2.2.0\n",
        f"{HOME}/backup_2026.tar.gz": "\0" * 4096,
        f"{HOME}/.bash_history": "sudo systemctl restart nginx\ncd /var/www/app\ngit pull\nsudo systemctl restart gunicorn\n",
        f"{HOME}/.profile": "# ~/.profile\n",
        f"{HOME}/.aws/credentials": f"[default]\naws_access_key_id = {aws_id}\naws_secret_access_key = {aws_sec}\n",
        f"{HOME}/.ssh/authorized_keys": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC0opsbastion ops@bastion\n",
        f"{HOME}/.ssh/known_hosts": "10.0.0.5 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIknownhost\n",
        "/var/www/app/app.py": "from flask import Flask\napp = Flask(__name__)\n",
        "/var/www/app/requirements.txt": "flask==3.0.0\nmysqlclient==2.2.0\n",
        "/var/www/app/.env": env,
        "/var/www/app/static/site.css": "body{margin:0}\n",
        "/var/backups/db_2026-10-18.sql.gz": "\0" * 20480,
        "/var/log/auth.log": "Oct 19 22:01:11 prod-app-01 sshd[811]: Accepted password for appadmin from 10.0.0.9 port 51122 ssh2\n",
        "/var/log/nginx/access.log": "10.0.0.22 - - [20/Oct/2026:09:12:01] \"GET / HTTP/1.1\" 200 512\n",
        "/etc/passwd": _PASSWD,
        "/etc/shadow": "root:!:19000:0:99999:7:::\nappadmin:$6$fakehash:19000:0:99999:7:::\n",
        "/etc/hostname": HOST + "\n",
        "/etc/os-release": 'PRETTY_NAME="Ubuntu 22.04.3 LTS"\n',
    }


def honey_overrides(pillar, token):
    """Fake data injected into a clone. Same paths as the real host, fake values."""
    return base_files(real=False, token=token)


_PS = ("USER       PID %CPU %MEM COMMAND\nroot         1  0.0  0.1 /sbin/init\nroot       811  0.0  0.1 sshd: /usr/sbin/sshd -D\n"
       "mysql      902  0.4  4.2 /usr/sbin/mysqld\nroot      1010  0.0  0.2 nginx: master process /usr/sbin/nginx\n"
       "www-data  1011  0.0  0.3 nginx: worker process\nappadmin  1204  0.2  1.1 gunicorn: master [app]\n"
       "appadmin  4310  0.0  0.1 -bash\n")
_SS = ("Netid State  Local Address:Port  Process\ntcp   LISTEN 0.0.0.0:22          sshd\ntcp   LISTEN 0.0.0.0:80          nginx\n"
       "tcp   LISTEN 127.0.0.1:3306      mysqld\ntcp   LISTEN 127.0.0.1:8000      gunicorn\n")
_IP = ("1: lo: <LOOPBACK,UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
       "2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500\n    inet 10.0.0.12/24 brd 10.0.0.255 scope global eth0\n")


class ShellEmulator:
    def __init__(self, files):
        self.fs = dict(files)
        self.cwd = HOME
        self.history = []
        self.extra_dirs = {"/tmp", "/root", "/var/www/app/static", f"{HOME}/logs"}

    # ---------------- helpers ----------------
    def _abs(self, p):
        if p.startswith("~"):
            p = HOME + p[1:]
        if not p.startswith("/"):
            p = posixpath.join(self.cwd, p)
        return posixpath.normpath(p)

    def _dirs(self):
        d = set(self.extra_dirs) | {"/"}
        for f in self.fs:
            parent = posixpath.dirname(f)
            while parent and parent != "/":
                d.add(parent); parent = posixpath.dirname(parent)
        return d

    def _children(self, path):
        out = set()
        for f in list(self.fs) + list(self._dirs()):
            if f != path and posixpath.dirname(f) == path:
                out.add(posixpath.basename(f))
        return sorted(out)

    # ---------------- public ----------------
    def replay(self, commands):
        """Re-apply state-changing earlier commands (cd, redirects) on a fresh clone."""
        for c in commands:
            self.run(c)

    def run(self, line):
        line = line.strip()
        self.history.append(line)
        outs = []
        for part in re.split(r"\s*(?:;|&&)\s*", line):
            if part:
                outs.append(self._pipeline(part))
        return "\n".join(o for o in outs if o is not None and o != "")

    # ---------------- parsing ----------------
    def _pipeline(self, seg):
        seg = re.sub(r"\s2>\s*/dev/null", "", seg)
        stages = [s.strip() for s in re.split(r"(?<!\|)\|(?!\|)", seg)]
        redirect = None
        m = re.search(r"\s(>>?)\s*(\S+)\s*$", stages[0])
        if m:
            redirect = (m.group(1), self._abs(m.group(2)))
            stages[0] = stages[0][:m.start()].strip()
        out = self._cmd(stages[0])
        for st in stages[1:]:
            out = self._filter(st, out)
        if redirect:
            mode, path = redirect
            content = out + ("\n" if out and not out.endswith("\n") else "")
            self.fs[path] = (self.fs.get(path, "") + content) if mode == ">>" else content
            return ""
        return out

    def _filter(self, st, text):
        try:
            a = shlex.split(st)
        except ValueError:
            return text
        if not a:
            return text
        lines = text.split("\n")
        if a[0] == "grep":
            pats = [x for x in a[1:] if not x.startswith("-")]
            flags = [x for x in a[1:] if x.startswith("-")]
            if not pats:
                return text
            ic = any("i" in f for f in flags)
            inv = any("v" in f for f in flags)
            pat = pats[0]
            hit = lambda l: (re.search(pat, l, re.I if ic else 0) is not None)
            return "\n".join(l for l in lines if hit(l) != inv)
        if a[0] in ("head", "tail"):
            n = 10
            for i, x in enumerate(a):
                if x == "-n" and i + 1 < len(a):
                    n = int(a[i + 1])
                elif re.fullmatch(r"-\d+", x):
                    n = int(x[1:])
            return "\n".join(lines[:n] if a[0] == "head" else lines[-n:])
        if a[0] == "wc" and "-l" in a:
            return str(len([l for l in lines if l]))
        return text

    # ---------------- commands ----------------
    def _cmd(self, c):
        if not c:
            return ""
        try:
            a = shlex.split(c)
        except ValueError:
            a = c.split()
        if not a:
            return ""
        n, args = a[0], a[1:]
        if n == "sudo":
            return "sudo: a password is required"
        fn = getattr(self, "c_" + n.replace("-", "_").replace(".", "_"), None)
        if fn:
            return fn(args)
        return f"bash: {n}: command not found"

    def c_whoami(s, a): return USER
    def c_hostname(s, a): return HOST
    def c_id(s, a): return f"uid=1000({USER}) gid=1000({USER}) groups=1000({USER})"
    def c_pwd(s, a): return s.cwd
    def c_uname(s, a): return f"Linux {HOST} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux" if "-a" in a else "Linux"
    def c_uptime(s, a): return " 09:41:02 up 37 days,  3:11,  1 user,  load average: 0.21, 0.18, 0.15"
    def c_date(s, a): return "Tue Oct 20 09:41:07 UTC 2026"
    def c_w(s, a): return f"{USER}  pts/0  10.0.0.9  09:30  0.00s  -bash"
    def c_df(s, a): return "Filesystem      Size  Used Avail Use% Mounted on\n/dev/sda1        40G   17G   21G  45% /"
    def c_free(s, a): return "              total        used        free\nMem:           7976        3120        1844"
    def c_ps(s, a): return _PS.rstrip("\n")
    def c_ss(s, a): return _SS.rstrip("\n")
    def c_netstat(s, a): return _SS.rstrip("\n")
    def c_ip(s, a): return _IP.rstrip("\n")
    def c_ifconfig(s, a): return _IP.rstrip("\n")
    def c_env(s, a):
        e = s.fs.get("/var/www/app/.env", "")
        return f"USER={USER}\nHOME={HOME}\nSHELL=/bin/bash\n" + "\n".join(l for l in e.split("\n") if l.startswith("DB_"))
    c_printenv = c_env
    def c_history(s, a): return "\n".join(f" {i+1}  {h}" for i, h in enumerate(s.history))
    def c_crontab(s, a): return f"no crontab for {USER}"
    def c_clear(s, a): return ""
    def c_echo(s, a): return " ".join(a)
    def c_touch(s, a):
        for x in a: s.fs.setdefault(s._abs(x), "")
        return ""
    def c_mkdir(s, a):
        for x in a:
            if not x.startswith("-"): s.extra_dirs.add(s._abs(x))
        return ""
    def c_rm(s, a):
        for x in a:
            if not x.startswith("-"): s.fs.pop(s._abs(x), None)
        return ""

    def c_cd(s, a):
        p = s._abs(a[0]) if a else HOME
        if p in s._dirs():
            s.cwd = p; return ""
        return f"bash: cd: {a[0]}: No such file or directory"

    def c_ls(s, a):
        flags = "".join(x for x in a if x.startswith("-"))
        paths = [x for x in a if not x.startswith("-")] or ["."]
        out = []
        for raw in paths:
            p = s._abs(raw)
            if p in s.fs:
                names, base = [posixpath.basename(p)], posixpath.dirname(p)
            elif p in s._dirs():
                names, base = s._children(p), p
            else:
                out.append(f"ls: cannot access '{raw}': No such file or directory"); continue
            if "a" not in flags:
                names = [x for x in names if not x.startswith(".")]
            if "l" in flags:
                rows = []
                for nm in names:
                    full = posixpath.join(base, nm)
                    if full in s.fs:
                        sz = len(s.fs[full]); rows.append(f"-rw-r--r-- 1 {USER} {USER} {sz:>6} Oct 18 09:12 {nm}")
                    else:
                        rows.append(f"drwxr-xr-x 2 {USER} {USER}   4096 Oct 18 09:12 {nm}")
                out.append(("total %d\n" % len(rows) if "h" not in flags or True else "") + "\n".join(rows))
            else:
                out.append("  ".join(names))
        return "\n".join(out)

    def _read(s, raw):
        p = s._abs(raw)
        if p in s.fs: return s.fs[p].rstrip("\n")
        if p in s._dirs(): return f"cat: {raw}: Is a directory"
        return f"cat: {raw}: No such file or directory"

    def c_cat(s, a): return "\n".join(s._read(x) for x in a if not x.startswith("-"))
    c_less = c_more = c_tac = c_strings = c_cat

    def _headtail(s, a, head):
        n, files = 10, []
        i = 0
        while i < len(a):
            if a[i] == "-n" and i + 1 < len(a): n = int(a[i + 1]); i += 2; continue
            if re.fullmatch(r"-\d+", a[i]): n = int(a[i][1:])
            elif not a[i].startswith("-"): files.append(a[i])
            i += 1
        txt = "\n".join(s._read(f) for f in files).split("\n")
        return "\n".join(txt[:n] if head else txt[-n:])
    def c_head(s, a): return s._headtail(a, True)
    def c_tail(s, a): return s._headtail(a, False)

    def c_grep(s, a):
        flags = [x for x in a if x.startswith("-")]
        rest = [x for x in a if not x.startswith("-")]
        if len(rest) < 2: return ""
        pat, target = rest[0], s._abs(rest[1])
        rec = any("r" in f.lower() for f in flags)
        ic = any("i" in f for f in flags)
        res = []
        for path in sorted(s.fs):
            if path == target or (rec and path.startswith(target.rstrip("/") + "/")):
                for line in s.fs[path].split("\n"):
                    if re.search(pat, line, re.I if ic else 0):
                        res.append(f"{path}:{line}" if (rec or target != path) else line)
        return "\n".join(res)

    def c_find(s, a):
        start = s._abs(a[0]) if a and not a[0].startswith("-") else s.cwd
        pats = [a[i + 1] for i, x in enumerate(a) if x == "-name" and i + 1 < len(a)]
        if "-perm" in a:
            return "/usr/bin/passwd\n/usr/bin/sudo\n/usr/bin/mount"
        hits = [p for p in sorted(s.fs) if (start == "/" or p.startswith(start.rstrip("/") + "/"))
                and (not pats or any(fnmatch.fnmatch(posixpath.basename(p), q) for q in pats))]
        return "\n".join(hits)

    def c_mysqldump(s, a):
        db = [x for x in a if not x.startswith("-")][-1] if [x for x in a if not x.startswith("-")] else "app"
        return (f"-- MySQL dump 10.13  Distrib 8.0.35\n-- Host: localhost    Database: {db}\n"
                "CREATE TABLE `customers` (`id` int, `name` varchar(80), `email` varchar(120), `card_last4` char(4));\n"
                "INSERT INTO `customers` VALUES (1,'A. Kumar','a.kumar@example.test','4242'),(2,'S. Devi','s.devi@example.test','1881');\n"
                "-- Dump completed\n")

    def c_mysql(s, a):
        return "id  name       email\n1   A. Kumar   a.kumar@example.test\n2   S. Devi    s.devi@example.test"

    def c_tar(s, a):
        flags = a[0] if a and a[0].startswith("-") or (a and re.fullmatch(r"[czxvf]+", a[0])) else ""
        rest = [x for x in a if x != flags]
        if "c" in flags and rest:
            out, srcs = s._abs(rest[0]), rest[1:]
            body = "".join(s.fs.get(s._abs(x), "") for x in srcs)
            s.fs[out] = "\0TAR\0" + body + "\0" * 1500
        return ""

    def c_scp(s, a):
        src = [x for x in a if not x.startswith("-") and "@" not in x and ":" not in x]
        name = posixpath.basename(src[0]) if src else "file"
        size = len(s.fs.get(s._abs(src[0]), "")) if src else 0
        return f"{name:<24}100% {max(size // 1024, 1):>5}KB   2.1MB/s   00:00"
    c_rsync = c_scp

    def c_wget(s, a):
        url = [x for x in a if x.startswith("http")]
        return f"--2026-10-20 09:42:10--  {url[0] if url else ''}\nConnecting... failed: Connection timed out."
    def c_curl(s, a): return "curl: (28) Failed to connect: Connection timed out"
    def c_nc(s, a): return ""
    def c_chmod(s, a): return ""
    def c_su(s, a): return "Password: \nsu: Authentication failure"
