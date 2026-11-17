"""Collection + normalization: heterogeneous raw logs -> one common event schema.

Each parser understands one native format.  Output columns:
  file, line, source, clock, ts (observed epoch seconds, still on the producer's
  clock), ts_res (timestamp resolution in s), user, src_ip, src_port, dst_ip,
  dst_port, action, status, bytes, req_id, aws_req, session, access_key, uri,
  host, msg
"""
import json
import os
import re
from datetime import datetime, timezone
from urllib.parse import unquote

import pandas as pd

from .config import LOG_FILES, HOSTS

COLS = ["file", "line", "source", "clock", "ts", "ts_res", "user", "src_ip", "src_port", "dst_ip",
        "dst_port", "action", "status", "bytes", "req_id", "aws_req", "session", "access_key", "uri",
        "host", "msg"]

WEB_RE = re.compile(r'^(\S+) - (\S+) \[([^\]]+)\] "(\S+) (\S+) [^"]*" (\d{3}) (\d+) "[^"]*" "([^"]*)" '
                    r'rid=(\S+) sport=(\d+)')
AUTH_RE = re.compile(r'^(\S+) (\S+) authd\[\d+\]: (LOGIN_\w+) user=(\S+) src=(\S+) sport=(\d+) '
                     r'session=(\S+) mfa=(\S+)')
VM_RE = re.compile(r'^(\w{3}\s+\d+ \d\d:\d\d:\d\d) (\S+) (\w+)\[(\d+)\]: (.*)$')
SSH_ACC = re.compile(r'Accepted \w+ for (\S+) from (\S+) port (\d+)')
SUDO = re.compile(r'^\s*(\S+) : TTY=\S+ ; PWD=\S+ ; USER=\S+ ; COMMAND=(.*)$')
PG = re.compile(r'connection authorized: user=(\S+) database=\S+ host=(\S+) port=(\d+)')
SESS = re.compile(r'session (opened|closed) for user (\w+)')


def _epoch(series, fmt="ISO8601", utc=True):
    dt = pd.to_datetime(series, format=fmt, utc=utc)
    return (dt - pd.Timestamp("1970-01-01", tz="UTC")).dt.total_seconds()


def _row(**kw):
    r = dict.fromkeys(COLS)
    r.update(kw)
    return r


def parse_web(path, fname, clock):
    rows = []
    host = fname.split(".")[0]
    with open(path) as fh:
        for i, ln in enumerate(fh):
            m = WEB_RE.match(ln)
            if not m:
                continue
            ip, user, ts, meth, uri, st, size, ua, rid, sport = m.groups()
            rows.append(_row(file=fname, line=i, source="web", clock=clock, ts=ts, ts_res=0.001,
                             user=None if user == "-" else user, src_ip=ip, src_port=int(sport),
                             dst_ip=HOSTS[host], dst_port=443, action=meth, status=int(st),
                             bytes=int(size), req_id=rid, uri=unquote(uri), host=host, msg=ua))
    df = pd.DataFrame(rows, columns=COLS)
    df["ts"] = _epoch(df["ts"])
    return df


def parse_app(path, fname, clock):
    rows = []
    with open(path) as fh:
        for i, ln in enumerate(fh):
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            extra = {k: v for k, v in d.items() if k not in
                     ("@timestamp", "level", "service", "host", "req_id", "user", "client_ip", "event", "endpoint")}
            rows.append(_row(file=fname, line=i, source="application", clock=clock, ts=d["@timestamp"],
                             ts_res=0.001, user=None if d.get("user") in (None, "-") else d["user"],
                             src_ip=d.get("client_ip"), action=d.get("event"), status=d.get("level"),
                             bytes=extra.get("rows"), req_id=d.get("req_id"),
                             aws_req=extra.get("aws_request_id"), uri=d.get("endpoint"),
                             host=d.get("host"), msg=json.dumps(extra) if extra else ""))
    df = pd.DataFrame(rows, columns=COLS)
    df["ts"] = _epoch(df["ts"])
    return df


def parse_auth(path, fname, clock):
    rows = []
    with open(path) as fh:
        for i, ln in enumerate(fh):
            m = AUTH_RE.match(ln)
            if not m:
                continue
            ts, host, tag, user, ip, sport, sess, mfa = m.groups()
            rows.append(_row(file=fname, line=i, source="security", clock=clock, ts=ts, ts_res=1e-6,
                             user=user, src_ip=ip, src_port=int(sport), dst_ip=HOSTS["idp-1"], dst_port=443,
                             action=tag, status="success" if tag == "LOGIN_SUCCESS" else "failure",
                             session=None if sess == "-" else sess, host=host, msg=f"mfa={mfa}"))
    df = pd.DataFrame(rows, columns=COLS)
    df["ts"] = _epoch(df["ts"])
    return df


def parse_flow(path, fname, clock):
    cols = ["ver", "acct", "eni", "src", "dst", "sport", "dport", "proto", "pk", "by", "start", "end",
            "act", "st"]
    raw = pd.read_csv(path, sep=" ", names=cols, header=None, dtype={"src": str, "dst": str})
    df = pd.DataFrame({c: None for c in COLS}, index=raw.index)
    df["file"] = fname
    df["line"] = raw.index
    df["source"] = "network"
    df["clock"] = clock
    # Flow start is truncated to whole seconds: centre of the 1 s bucket is the best estimate
    df["ts"] = raw["start"].astype(float) + 0.5
    df["ts_res"] = 1.0
    df["src_ip"] = raw["src"]
    df["dst_ip"] = raw["dst"]
    df["src_port"] = raw["sport"]
    df["dst_port"] = raw["dport"]
    df["bytes"] = raw["by"]
    df["action"] = raw["act"]
    df["msg"] = "dur=" + (raw["end"] - raw["start"]).astype(str)
    df["host"] = "vpc"
    return df[COLS]


def parse_trail(path, fname, clock):
    rows = []
    with open(path) as fh:
        for i, ln in enumerate(fh):
            try:
                d = json.loads(ln)
            except json.JSONDecodeError:
                continue
            ui = d.get("userIdentity", {})
            rp = d.get("requestParameters") or {}
            rows.append(_row(file=fname, line=i, source="audit", clock=clock, ts=d["eventTime"], ts_res=1.0,
                             user=ui.get("userName"), src_ip=d.get("sourceIPAddress"),
                             action=d.get("eventName"), status="ok", aws_req=d.get("requestID"),
                             access_key=ui.get("accessKeyId"), uri=d.get("eventSource"),
                             host="cloudtrail", msg=json.dumps(rp)))
    df = pd.DataFrame(rows, columns=COLS)
    # second-resolution timestamps: centre of the bucket
    df["ts"] = _epoch(df["ts"]) + 0.5
    return df


def parse_vm(path, fname, clock, year=2026):
    rows = []
    with open(path) as fh:
        for i, ln in enumerate(fh):
            m = VM_RE.match(ln.rstrip("\n"))
            if not m:
                continue
            ts, host, prog, pid, body = m.groups()
            r = _row(file=fname, line=i, source="system", clock=clock, ts=f"{year} {ts}", ts_res=1.0,
                     host=host, action=prog, msg=body, session=f"{host}:{prog}:{pid}")
            a = SSH_ACC.search(body)
            if a:
                r.update(user=a.group(1), src_ip=a.group(2), src_port=int(a.group(3)),
                         dst_ip=HOSTS[host], dst_port=22, action="ssh_accept")
            s = SUDO.match(body)
            if s:
                r.update(user=s.group(1), action="sudo", uri=s.group(2))
            p = PG.search(body)
            if p:
                r.update(user=p.group(1), src_ip=p.group(2), src_port=int(p.group(3)),
                         dst_ip=HOSTS[host], dst_port=5432, action="pg_connect")
            se = SESS.search(body)
            if se:
                r.update(user=se.group(2), action="session_" + se.group(1))
            rows.append(r)
    df = pd.DataFrame(rows, columns=COLS)
    # BSD syslog has no year; inferred from collection context. Second resolution -> centre bucket
    df["ts"] = _epoch(df["ts"], "%Y %b %d %H:%M:%S") + 0.5
    return df


PARSERS = {"web": parse_web, "application": parse_app, "security": parse_auth, "network": parse_flow,
           "audit": parse_trail, "system": parse_vm}


def load_case(case_dir, sources=None, files=None):
    """Collect every log file of a case directory and return the normalized frame."""
    frames = []
    for fname, (src, clock) in LOG_FILES.items():
        if sources is not None and src not in sources:
            continue
        p = os.path.join(case_dir, fname) if files is None else files.get(fname)
        if p is None or not os.path.exists(p):
            continue
        frames.append(PARSERS[src](p, fname, clock))
    df = pd.concat(frames, ignore_index=True)
    for c in ("src_port", "dst_port", "bytes"):
        df[c] = pd.to_numeric(df[c], errors="coerce")
    df["ts"] = df["ts"].astype(float)
    return df


def attach_ground_truth(df, case_dir):
    gt = pd.read_csv(os.path.join(case_dir, "_ground_truth.csv"), keep_default_na=False)
    return df.merge(gt, on=["file", "line"], how="left")
