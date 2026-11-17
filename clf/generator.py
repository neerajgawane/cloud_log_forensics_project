"""Synthetic multi-source cloud log generator with ground truth.

Produces realistic, heterogeneous raw log files (nginx-style access logs,
JSON application logs, syslog authentication logs, AWS VPC flow logs v2,
CloudTrail JSON and BSD syslog from a VM).  Every host stamps records with
its *own* clock (offset + drift), so the raw timestamps disagree just as they
do in a real distributed deployment.  A seven-stage intrusion (modelled on the
Heartland and Buzz Coffee cases discussed by Khan et al.) is injected into
benign background traffic that also contains deliberately suspicious-looking
but legitimate activity (false-positive bait).

Ground truth (true time, benign/attack label and attack stage) is written to a
separate CSV keyed by (file, line) and is never visible to the pipeline.
"""
import json
import os
from datetime import datetime, timezone

import numpy as np

from .config import HOSTS, T0, CLOCK_DOMAINS, REFERENCE_CLOCK, LOG_FILES

ENDPOINTS = ["/api/items", "/api/items/{id}", "/api/cart", "/api/orders", "/api/profile",
             "/api/search?q={q}", "/api/upload", "/", "/static/app.js", "/static/style.css"]
WORDS = ["shoes", "laptop", "coffee", "bag", "phone", "desk", "lamp", "book", "pen", "watch"]
RECON_PATHS = ["/admin", "/.git/config", "/wp-login.php", "/backup.zip", "/.env", "/phpmyadmin",
               "/server-status", "/config.json", "/api/v1/debug", "/actuator/env", "/db.sql",
               "/.aws/credentials", "/console", "/manager/html", "/cgi-bin/test.cgi", "/old/"]
SQLI_PAYLOADS = ["shoes%27", "shoes%27%20OR%201%3D1--", "x%27%20UNION%20SELECT%20null,null--",
                 "x%27%20UNION%20SELECT%20username,password%20FROM%20users--",
                 "x%27%20UNION%20SELECT%20email,card_hash%20FROM%20customers--"]
UA = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5)",
      "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0)", "okhttp/4.12.0"]

ATTACKER_IP = "185.220.101.47"
EXFIL_IP = "45.137.21.9"


class ClockModel:
    """Per-domain clock: observed = true + offset + drift_ppm*1e-6*(true-T0)."""

    def __init__(self, rng, max_offset=2.0, max_drift_ppm=50.0):
        self.params = {}
        for d in CLOCK_DOMAINS:
            if d == REFERENCE_CLOCK:
                self.params[d] = (0.0, 0.0)
            else:
                self.params[d] = (float(rng.uniform(-max_offset, max_offset)),
                                  float(rng.uniform(-max_drift_ppm, max_drift_ppm)))

    def obs(self, domain, t):
        off, ppm = self.params[domain]
        return t + off + ppm * 1e-6 * (t - T0)


def iso_ms(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]


def iso_s(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def bsd(t):
    d = datetime.fromtimestamp(t, tz=timezone.utc)
    return d.strftime("%b ") + f"{d.day:2d}" + d.strftime(" %H:%M:%S")


class Generator:
    def __init__(self, seed=0, hours=4.0, web_rate=1.5, max_offset=2.0, max_drift_ppm=50.0,
                 attack=True, attack_frac=None):
        self.rng = np.random.default_rng(seed)
        self.seed = seed
        self.hours = hours
        self.dur = hours * 3600.0
        self.web_rate = web_rate
        self.clock = ClockModel(self.rng, max_offset, max_drift_ppm)
        self.attack = attack
        self.attack_frac = attack_frac
        self.events = []  # dicts with t, file, payload(fn), label, stage
        self.users = [f"u{i:03d}" for i in range(300)]
        self.user_ip = {u: self._public_ip() for u in self.users}
        self._gid = 0

    # ------------------------------------------------------------------ utils
    def _public_ip(self):
        r = self.rng
        first = int(r.choice([24, 49, 59, 73, 98, 103, 117, 122, 157, 182, 203]))
        return f"{first}.{r.integers(1, 255)}.{r.integers(0, 255)}.{r.integers(1, 255)}"

    def _hex(self, n):
        return "".join(self.rng.choice(list("0123456789abcdef"), n))

    def _port(self):
        return int(self.rng.integers(32768, 61000))

    def _emit(self, t, file, kind, label="benign", stage="", **kw):
        self._gid += 1
        self.events.append(dict(t=float(t), file=file, kind=kind, label=label, stage=stage,
                                gid=self._gid, **kw))

    # ------------------------------------------------------- composite events
    def web_request(self, t, ip, user, method, path, status, host, label="benign", stage="",
                    app=True, app_events=None, ua=None, size=None):
        sport = self._port()
        rid = self._hex(16)
        size = size if size is not None else int(self.rng.integers(200, 20000))
        ua = ua or UA[int(self.rng.integers(0, len(UA)))]
        # TCP connection opens shortly before the request is served
        t_conn = t - float(self.rng.uniform(0.005, 0.08))
        self._emit(t_conn, "vpc-flow.log", "flow", label, stage, src=ip, dst=HOSTS[host], sport=sport,
                   dport=443, proto=6, packets=int(self.rng.integers(4, 40)), bytes=size + 600,
                   dur=float(self.rng.uniform(0.05, 3.0)), action="ACCEPT")
        self._emit(t, f"{host}.access.log", "web", label, stage, ip=ip, user=user, method=method,
                   path=path, status=status, size=size, ua=ua, rid=rid, sport=sport, host=host)
        if app:
            evs = app_events or [("INFO", "request.handled", {})]
            tt = t + float(self.rng.uniform(0.004, 0.04))
            for lvl, ev, extra in evs:
                self._emit(tt, "app-1.jsonl", "app", label, stage, level=lvl, event=ev, rid=rid,
                           user=user, ip=ip, endpoint=path.split("?")[0], extra=extra)
                tt += float(self.rng.uniform(0.001, 0.02))
        return rid

    def login(self, t, user, ip, ok=True, label="benign", stage="", mfa=True):
        sport = self._port()
        sess = "s-" + self._hex(10) if ok else "-"
        self._emit(t - float(self.rng.uniform(0.01, 0.2)), "vpc-flow.log", "flow", label, stage, src=ip,
                   dst=HOSTS["idp-1"], sport=sport, dport=443, proto=6,
                   packets=int(self.rng.integers(8, 30)), bytes=int(self.rng.integers(2000, 9000)),
                   dur=float(self.rng.uniform(0.2, 2.0)), action="ACCEPT")
        self._emit(t, "idp-1.auth.log", "auth", label, stage, ok=ok, user=user, ip=ip, sport=sport,
                   session=sess, mfa=mfa)
        return sess

    def trail(self, t, name, user, ip, label="benign", stage="", ak=None, params=None, req=None,
              source="iam.amazonaws.com"):
        self._emit(t, "cloudtrail.jsonl", "trail", label, stage, name=name, user=user, ip=ip,
                   ak=ak or "AKIA" + self._hex(16).upper(), params=params or {},
                   req=req or self._hex(8) + "-" + self._hex(4) + "-" + self._hex(12),
                   esrc=source)

    def ssh_session(self, t, user, src_ip, cmds, label="benign", stage="", sudo_gap=(5, 40)):
        sport = self._port()
        pid = int(self.rng.integers(2000, 40000))
        self._emit(t - float(self.rng.uniform(0.05, 0.4)), "vpc-flow.log", "flow", label, stage, src=src_ip,
                   dst=HOSTS["vm-db-1"], sport=sport, dport=22, proto=6,
                   packets=int(self.rng.integers(30, 400)), bytes=int(self.rng.integers(5000, 90000)),
                   dur=float(self.rng.uniform(20, 300)), action="ACCEPT")
        self._emit(t, "vm-db-1.syslog", "vm", label, stage,
                   msg=f"sshd[{pid}]: Accepted publickey for {user} from {src_ip} port {sport} ssh2")
        self._emit(t + 0.05, "vm-db-1.syslog", "vm", label, stage,
                   msg=f"sshd[{pid}]: pam_unix(sshd:session): session opened for user {user}(uid=1001) by (uid=0)")
        tt = t + 1.0
        for c in cmds:
            tt += float(self.rng.uniform(*sudo_gap))
            sp = int(self.rng.integers(2000, 40000))
            self._emit(tt, "vm-db-1.syslog", "vm", label, stage,
                       msg=f"sudo[{sp}]: {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND={c}")
        self._emit(tt + float(self.rng.uniform(2, 30)), "vm-db-1.syslog", "vm", label, stage,
                   msg=f"sshd[{pid}]: pam_unix(sshd:session): session closed for user {user}")
        return tt

    def flow(self, t, src, dst, dport, nbytes, label="benign", stage="", dur=60.0):
        self._emit(t, "vpc-flow.log", "flow", label, stage, src=src, dst=dst, sport=self._port(),
                   dport=dport, proto=6, packets=max(1, nbytes // 1400), bytes=int(nbytes), dur=dur,
                   action="ACCEPT")

    # -------------------------------------------------------------- benign
    def benign(self):
        r = self.rng
        D = self.dur
        # Web traffic (Poisson)
        n_web = r.poisson(self.web_rate * D)
        ts = np.sort(r.uniform(0, D, n_web)) + T0
        for t in ts:
            u = self.users[int(r.integers(0, len(self.users)))]
            ip = self.user_ip[u]
            ep = ENDPOINTS[int(r.integers(0, len(ENDPOINTS)))]
            path = ep.replace("{id}", str(int(r.integers(1, 5000)))).replace(
                "{q}", WORDS[int(r.integers(0, len(WORDS)))])
            host = "web-1" if r.random() < 0.5 else "web-2"
            method = "POST" if ep == "/api/upload" else "GET"
            p = r.random()
            status = 404 if p < 0.01 else (500 if p < 0.012 else 200)
            is_api = path.startswith("/api")
            if ep == "/api/upload" and status == 200:
                areq = self._hex(8) + "-" + self._hex(4) + "-" + self._hex(12)
                key = f"uploads/{u}/{self._hex(8)}.jpg"
                self.web_request(t, ip, u, method, path, status, host,
                                 app_events=[("INFO", "s3.put_object", {"key": key, "aws_request_id": areq}),
                                             ("INFO", "request.handled", {})])
                self.trail(t + float(r.uniform(0.03, 0.15)), "PutObject", "svc-app", HOSTS["app-1"],
                           params={"bucketName": "user-uploads", "key": key}, req=areq,
                           ak="AKIASVCAPP0000000001", source="s3.amazonaws.com")
            else:
                evs = [("INFO", "request.handled", {})] if status == 200 else (
                    [("WARN", "route.not_found", {})] if status == 404 else [("ERROR", "unhandled.exception", {"err": "TimeoutError"})])
                self.web_request(t, ip, u, method, path, status, host, app=is_api, app_events=evs)
        # Interactive logins (some failures)
        for t in np.sort(r.uniform(0, D, r.poisson(0.05 * D))) + T0:
            u = self.users[int(r.integers(0, len(self.users)))]
            ok = r.random() > 0.06
            self.login(t, u, self.user_ip[u], ok=ok)
        # Failed-login burst by a legitimate user who forgot the password
        tb = T0 + r.uniform(0.1, 0.9) * D
        u = self.users[7]
        for k in range(6):
            self.login(tb + 7 * k, u, self.user_ip[u], ok=(k == 5))
        # Service account svc-backup used legitimately from backup host
        for t in np.arange(T0 + 600, T0 + D, 1800):
            self.login(t, "svc-backup", HOSTS["backup-1"], ok=True, mfa=False)
            for k in range(3):
                self.trail(t + 20 + k * 5, "PutObject", "svc-backup", HOSTS["backup-1"],
                           ak="AKIABACKUP0000000001", source="s3.amazonaws.com",
                           params={"bucketName": "db-backups", "key": f"nightly/{self._hex(6)}.dump"})
        # Ops administrator control-plane activity
        for t in np.sort(r.uniform(0, D, r.poisson(D / 120))) + T0:
            self.trail(t, str(r.choice(["DescribeInstances", "ListBuckets", "GetMetricData",
                                        "DescribeSecurityGroups", "ListUsers"])),
                       "ops-admin", HOSTS["jump-1"], ak="AKIAOPSADMIN00000001",
                       source="ec2.amazonaws.com")
        # Legitimate (but alert-worthy) key rotation by ops
        self.trail(T0 + r.uniform(0.05, 0.95) * D, "CreateAccessKey", "ops-admin", HOSTS["jump-1"],
                   ak="AKIAOPSADMIN00000001", params={"userName": "svc-reporting"})
        # Ops SSH maintenance sessions
        for t in np.arange(T0 + r.uniform(60, 900), T0 + D, 900.0):
            self.ssh_session(t + r.uniform(-60, 60), "ops", HOSTS["jump-1"],
                             ["/usr/bin/systemctl status postgresql"])
        # App -> DB connection churn (postgres logs connection to syslog)
        for t in np.arange(T0 + 5, T0 + D, 20.0):
            tt = t + r.uniform(-3, 3)
            sport = self._port()
            self._emit(tt - r.uniform(0.002, 0.02), "vpc-flow.log", "flow", src=HOSTS["app-1"],
                       dst=HOSTS["vm-db-1"], sport=sport, dport=5432, proto=6,
                       packets=int(r.integers(10, 200)), bytes=int(r.integers(4000, 400000)),
                       dur=float(r.uniform(5, 60)), action="ACCEPT")
            pid = int(r.integers(2000, 40000))
            self._emit(tt, "vm-db-1.syslog", "vm",
                       msg=f"postgres[{pid}]: connection authorized: user=orders database=orders host={HOSTS['app-1']} port={sport}")
        # Cron on the VM
        for t in np.arange(T0 + 30, T0 + D, 300.0):
            self._emit(t, "vm-db-1.syslog", "vm",
                       msg=f"CRON[{int(r.integers(2000, 40000))}]: (postgres) CMD (/usr/local/bin/pg_stat_collect)")
        # Nightly backup egress to sanctioned object storage
        for t in np.arange(T0 + 1200, T0 + D, 7200.0):
            self.flow(t, HOSTS["vm-db-1"], "52.219.66.12", 443, int(r.integers(6e8, 9e8)), dur=420)
        # Internal vulnerability scanner (404 burst, benign)
        ts0 = T0 + r.uniform(0.05, 0.95) * D
        for k in range(60):
            self.web_request(ts0 + k * 1.5, HOSTS["scanner-1"], "-", "GET",
                             RECON_PATHS[k % len(RECON_PATHS)], 404, "web-2", app=False,
                             ua="Nessus/10.6")
        # Developer pushing a large artifact to an external CDN (benign egress alert)
        self.flow(T0 + r.uniform(0.05, 0.95) * D, HOSTS["app-1"], "151.101.1.69", 443, 350_000_000, dur=90)

    # -------------------------------------------------------------- attack
    def attack_scenario(self):
        r = self.rng
        frac = self.attack_frac if self.attack_frac is not None else r.uniform(0.25, 0.45)
        ta = T0 + frac * self.dur
        self.attack_start = ta
        A, X = ATTACKER_IP, EXFIL_IP
        L = "attack"
        evil_ua = "python-requests/2.31.0"
        # 1. Reconnaissance: forced browsing -> 404s
        for k in range(int(r.integers(45, 70))):
            self.web_request(ta + k * r.uniform(1.0, 2.5), A, "-", "GET",
                             RECON_PATHS[int(r.integers(0, len(RECON_PATHS)))], 404, "web-1",
                             label=L, stage="recon", app=False, ua=evil_ua)
        # 2. Initial access: SQL injection against /api/search
        t = ta + 300 + r.uniform(0, 60)
        for k, p in enumerate(SQLI_PAYLOADS + SQLI_PAYLOADS[-2:]):
            ok = k >= 2
            status = 200 if ok else 500
            ev = ([("INFO", "db.query", {"rows": int(r.integers(30000, 60000))}), ("INFO", "request.handled", {})]
                  if ok else [("ERROR", "db.error", {"err": "syntax error at or near \"'\""})])
            self.web_request(t, A, "-", "GET", f"/api/search?q={p}", status, "web-1", label=L,
                             stage="initial_access", app_events=ev, ua=evil_ua,
                             size=int(r.integers(2e5, 4e6)) if ok else 512)
            t += r.uniform(8, 40)
        # 3. Credential access: harvested svc-backup password used from attacker IP
        t = ta + 900 + r.uniform(0, 120)
        self.login(t, "svc-backup", A, ok=False, label=L, stage="credential_access", mfa=False)
        self.login(t + 11, "svc-backup", A, ok=False, label=L, stage="credential_access", mfa=False)
        self.login(t + 25, "svc-backup", A, ok=True, label=L, stage="credential_access", mfa=False)
        # 4. Privilege escalation via IAM
        t += 90
        ak_old = "AKIABACKUP0000000001"
        ak_new = "AKIA" + self._hex(16).upper()
        for name, params in [("GetCallerIdentity", {}), ("ListUsers", {}),
                             ("ListAttachedUserPolicies", {"userName": "svc-backup"}),
                             ("CreateAccessKey", {"userName": "svc-backup"}),
                             ("AttachUserPolicy", {"userName": "svc-backup",
                                                   "policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})]:
            self.trail(t, name, "svc-backup", A, label=L, stage="privilege_escalation", ak=ak_old,
                       params=params)
            t += r.uniform(10, 45)
        self.trail(t + 30, "GetCallerIdentity", "svc-backup", A, label=L, stage="privilege_escalation",
                   ak=ak_new, source="sts.amazonaws.com")
        # 5. Lateral movement: pivot from compromised web-1 into the DB VM
        t = ta + 1500 + r.uniform(0, 120)
        tend = self.ssh_session(t, "dbadmin", HOSTS["web-1"],
                                ["/usr/bin/pg_dump -Fc customers -f /tmp/.c.dump",
                                 "/usr/bin/tar czf /tmp/.c.tgz /tmp/.c.dump"],
                                label=L, stage="lateral_movement")
        # 6. Exfiltration: bulk egress + S3 bulk reads with the new key
        t = tend + 60
        for k in range(4):
            self.flow(t + k * 95, HOSTS["vm-db-1"], X, 443, int(r.integers(2.5e8, 3.5e8)), label=L,
                      stage="exfiltration", dur=90)
        ts3 = t + 30
        for k in range(int(r.integers(25, 40))):
            self.trail(ts3 + k * r.uniform(2, 8), "GetObject", "svc-backup", A, label=L,
                       stage="exfiltration", ak=ak_new, source="s3.amazonaws.com",
                       params={"bucketName": "customer-exports", "key": f"exports/2026/part-{k:04d}.parquet"})
        # 7. Defense evasion: tamper with local logs and stop the trail
        t = t + 600
        self.ssh_session(t, "dbadmin", HOSTS["web-1"],
                         ["/usr/bin/truncate -s 0 /var/log/auth.log",
                          "/usr/bin/rm -f /root/.bash_history /tmp/.c.dump /tmp/.c.tgz"],
                         label=L, stage="defense_evasion", sudo_gap=(3, 10))
        self.trail(t + 120, "StopLogging", "svc-backup", A, label=L, stage="defense_evasion",
                   ak=ak_new, source="cloudtrail.amazonaws.com", params={"name": "org-trail"})
        self.attack_end = t + 120
        self.attack_keys = {"ak_new": ak_new}

    # -------------------------------------------------------------- render
    def render(self, ev):
        k = ev["kind"]
        dom = LOG_FILES[ev["file"]][1]
        to = self.clock.obs(dom, ev["t"])
        if k == "web":
            return (f'{ev["ip"]} - {ev["user"]} [{iso_ms(to)}+00:00] "{ev["method"]} {ev["path"]} HTTP/1.1" '
                    f'{ev["status"]} {ev["size"]} "-" "{ev["ua"]}" rid={ev["rid"]} sport={ev["sport"]}')
        if k == "app":
            d = {"@timestamp": iso_ms(to) + "Z", "level": ev["level"], "service": "orders-api",
                 "host": "app-1", "req_id": ev["rid"], "user": ev["user"], "client_ip": ev["ip"],
                 "event": ev["event"], "endpoint": ev["endpoint"]}
            d.update(ev["extra"])
            return json.dumps(d)
        if k == "auth":
            dt = datetime.fromtimestamp(to, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")
            tag = "LOGIN_SUCCESS" if ev["ok"] else "LOGIN_FAILURE"
            return (f'{dt}+00:00 idp-1 authd[812]: {tag} user={ev["user"]} src={ev["ip"]} '
                    f'sport={ev["sport"]} session={ev["session"]} mfa={str(ev["mfa"]).lower()}')
        if k == "flow":
            st = int(to)
            en = int(to + ev["dur"])
            return (f'2 123456789012 eni-0a1b2c3d {ev["src"]} {ev["dst"]} {ev["sport"]} {ev["dport"]} '
                    f'{ev["proto"]} {ev["packets"]} {ev["bytes"]} {st} {en} {ev["action"]} OK')
        if k == "trail":
            d = {"eventVersion": "1.08", "eventTime": iso_s(to), "eventSource": ev["esrc"],
                 "eventName": ev["name"], "awsRegion": "ap-south-1", "sourceIPAddress": ev["ip"],
                 "userIdentity": {"type": "IAMUser", "userName": ev["user"], "accessKeyId": ev["ak"]},
                 "requestParameters": ev["params"], "requestID": ev["req"]}
            return json.dumps(d)
        if k == "vm":
            return f'{bsd(to)} vm-db-1 {ev["msg"]}'
        raise ValueError(k)

    def generate(self, outdir):
        self.benign()
        if self.attack:
            self.attack_scenario()
        os.makedirs(outdir, exist_ok=True)
        by_file = {f: [] for f in LOG_FILES}
        for ev in self.events:
            by_file[ev["file"]].append(ev)
        gt = ["file,line,gid,label,stage,true_ts"]
        for f, evs in by_file.items():
            evs.sort(key=lambda e: e["t"])
            with open(os.path.join(outdir, f), "w") as fh:
                for i, ev in enumerate(evs):
                    fh.write(self.render(ev) + "\n")
                    gt.append(f'{f},{i},{ev["gid"]},{ev["label"]},{ev["stage"]},{ev["t"]:.6f}')
        with open(os.path.join(outdir, "_ground_truth.csv"), "w") as fh:
            fh.write("\n".join(gt) + "\n")
        meta = {"seed": self.seed, "hours": self.hours, "clock": self.clock.params,
                "n_events": len(self.events),
                "attack_start": getattr(self, "attack_start", None),
                "attack_end": getattr(self, "attack_end", None)}
        with open(os.path.join(outdir, "_meta.json"), "w") as fh:
            json.dump(meta, fh, indent=1)
        return meta
