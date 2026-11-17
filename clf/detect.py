"""Analysis stage 1: rule-based detection over the normalized, synchronized events.

Each rule emits alerts carrying the *entities* (IPs, users, access keys,
sessions, hosts) that later drive cross-source correlation.  Rules operate on
normalized fields only, so the same rule works on raw or pseudonymized data as
long as the coarse attributes (ip_class, user_role) are preserved.
"""
import re

import pandas as pd

from .config import HOSTS

SQLI_RE = re.compile(r"(?:'|%27)\s*(?:or|and)\s+\d+=\d+|union\s+select|--\s*$|'\s*$", re.I)
TAMPER_RE = re.compile(r"(?:truncate\s+-s\s*0\s+/var/log|rm\s+(?:-\w+\s+)*\S*(?:\.bash_history|/var/log)|history\s+-c|"
                       r"auditctl\s+-D|systemctl\s+stop\s+(?:rsyslog|auditd))", re.I)
HIGH_RISK_API = {"CreateAccessKey", "AttachUserPolicy", "PutUserPolicy", "StopLogging", "DeleteTrail",
                 "UpdateAssumeRolePolicy", "CreateLoginProfile", "PutBucketPolicy"}

RULES = {
    "R1_web_404_burst": "≥20 HTTP 404 responses from one client within 60 s",
    "R2_sqli": "SQL-injection signature in request or DB syntax error in application",
    "R3_svc_login_external": "Service/admin account authenticates from an external address",
    "R4_high_risk_iam": "High-risk control-plane API call (key creation, policy attach, logging stop)",
    "R5_web_to_db_ssh": "SSH from the web tier into the database tier",
    "R6_bulk_egress": "≥200 MB outbound to a non-allowlisted external destination",
    "R7_log_tampering": "Command that clears or truncates logs / shell history",
    "R8_bulk_object_read": "≥15 object reads by one principal within 5 minutes",
}


def add_attributes(df):
    """Coarse, privacy-safe attributes computed before any pseudonymization."""
    out = df.copy()

    def ipc(ip):
        if not isinstance(ip, str):
            return None
        if ip.startswith("10.0.1."):
            return "web_tier"
        if ip.startswith("10.0.4."):
            return "db_tier"
        if ip.startswith("10."):
            return "internal"
        if ip.startswith(("52.216.", "52.217.", "52.218.", "52.219.")):
            return "allowlisted"
        return "external"
    out["src_class"] = out.src_ip.map(ipc)
    out["dst_class"] = out.dst_ip.map(ipc)
    out["user_role"] = out.user.map(lambda u: None if not isinstance(u, str) else
                                    ("service" if u.startswith("svc-") else
                                     "admin" if u in ("ops-admin", "root", "ops", "dbadmin") else "user"))
    return out


def _alert(rule, rows, entities):
    return {"rule": rule, "eids": list(rows.index), "t0": float(rows.t.min()), "t1": float(rows.t.max()),
            "entities": sorted(set(e for e in entities if e))}


def host_entity(h):
    ip = HOSTS.get(h)
    return f"ip:{ip}" if ip else f"host:{h}"


def detect(df):
    """df must contain synchronized time column `t` and attributes. Returns list of alerts."""
    alerts = []
    web = df[df.source == "web"]
    app = df[df.source == "application"]
    sec = df[df.source == "security"]
    net = df[df.source == "network"]
    aud = df[df.source == "audit"]
    vm = df[df.source == "system"]

    # R1: 404 bursts per client IP (rolling 60 s window)
    w404 = web[web.status == 404].sort_values("t")
    for ip, g in w404.groupby("src_ip"):
        if len(g) < 20:
            continue
        tt = g.t.to_numpy()
        j = 0
        for i in range(len(tt)):
            while tt[i] - tt[j] > 60:
                j += 1
            if i - j + 1 >= 20:
                alerts.append(_alert("R1_web_404_burst", g, [f"ip:{ip}"]))
                break

    # R2: SQL injection (web URI signature, application DB syntax error)
    hits = web[web.uri.fillna("").str.contains(SQLI_RE)]
    for ip, g in hits.groupby("src_ip"):
        ents = [f"ip:{ip}"] + [host_entity(h) for h in g.host.unique()] + [f"req:{r}" for r in g.req_id]
        alerts.append(_alert("R2_sqli", g, ents))
    dberr = app[(app.action == "db.error") & app.msg.fillna("").str.contains("syntax error")]
    for ip, g in dberr.groupby("src_ip"):
        alerts.append(_alert("R2_sqli", g, [f"ip:{ip}"] + [f"req:{r}" for r in g.req_id]))

    # R3: service / admin account login from outside the corporate network
    s3 = sec[(sec.user_role.isin(["service", "admin"])) & (sec.src_class == "external")]
    for (u, ip), g in s3.groupby(["user", "src_ip"]):
        ents = [f"user:{u}", f"ip:{ip}"] + [f"sess:{s}" for s in g.session.dropna()]
        alerts.append(_alert("R3_svc_login_external", g, ents))

    # R4: high-risk IAM / logging API calls
    a4 = aud[aud.action.isin(HIGH_RISK_API)]
    for (u, ip), g in a4.groupby(["user", "src_ip"]):
        ents = [f"user:{u}", f"ip:{ip}"] + [f"ak:{k}" for k in g.access_key.dropna().unique()]
        alerts.append(_alert("R4_high_risk_iam", g, ents))

    # R5: SSH from web tier to db tier (network or host view)
    n5 = net[(net.dst_port == 22) & (net.src_class == "web_tier") & (net.dst_class == "db_tier")]
    v5 = vm[(vm.action == "ssh_accept") & (vm.src_class == "web_tier")]
    for g in (n5, v5):
        for ip, gg in g.groupby("src_ip"):
            dsts = [f"ip:{d}" for d in gg.dst_ip.dropna().unique()]
            ents = [f"ip:{ip}"] + dsts + [f"user:{u}@vm-db-1" for u in gg.user.dropna().unique()]
            alerts.append(_alert("R5_web_to_db_ssh", gg, ents))

    # R6: bulk egress to non-allowlisted external destination
    n6 = net[(net.dst_class == "external") & (net.bytes >= 200e6)]
    for (s, d), g in n6.groupby(["src_ip", "dst_ip"]):
        alerts.append(_alert("R6_bulk_egress", g, [f"ip:{s}", f"ip:{d}"]))

    # R7: log / history tampering on hosts
    v7 = vm[(vm.action == "sudo") & vm.uri.fillna("").str.contains(TAMPER_RE)]
    for u, g in v7.groupby("user"):
        alerts.append(_alert("R7_log_tampering", g, [f"user:{u}@vm-db-1", host_entity("vm-db-1")]))

    # R8: bulk object reads by one principal (5-minute tumbling windows)
    a8 = aud[aud.action == "GetObject"].copy()
    if len(a8):
        a8["win"] = (a8.t // 300).astype(int)
        for (u, ak, win), g in a8.groupby(["user", "access_key", "win"]):
            if len(g) >= 15:
                ents = [f"user:{u}", f"ak:{ak}"] + [f"ip:{i}" for i in g.src_ip.unique()]
                alerts.append(_alert("R8_bulk_object_read", g, ents))
    return alerts
