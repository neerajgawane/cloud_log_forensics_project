"""Report stage: forensic incident report with timeline and chain of custody."""
from datetime import datetime, timezone

from .detect import RULES


def _ts(t):
    return datetime.fromtimestamp(t, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def _describe(r):
    s = r.source
    if s == "web":
        return f'{r.src_ip} {r.action} {r.uri} -> {int(r.status)}'
    if s == "application":
        return f'{r.action} req={r.req_id} {r.msg or ""}'[:110]
    if s == "security":
        return f'{r.action} user={r.user} from {r.src_ip}'
    if s == "network":
        return f'{r.src_ip}:{int(r.src_port)} -> {r.dst_ip}:{int(r.dst_port)} {int(r.bytes):,} B'
    if s == "audit":
        return f'{r.action} by {r.user} ({r.access_key}) from {r.src_ip}'
    if s == "system":
        if r.action == "ssh_accept":
            return f'SSH login {r.user} from {r.src_ip}'
        uri = r.uri if isinstance(r.uri, str) else ""
        return f'{r.action} {r.user if isinstance(r.user, str) else ""} {uri}'.strip()[:110]
    return ""


def incident_report(res, case_id="CASE-2026-001", max_rows=60):
    inc = res["incidents"][0] if res["incidents"] else None
    L = [f"# Forensic Incident Report — {case_id}", ""]
    if inc is None:
        L.append("No corroborated incident was found.")
        return "\n".join(L)
    tl = inc["timeline"]
    L += [f"**Incident window (reference clock, UTC):** {_ts(inc['span'][0])} → {_ts(inc['span'][1])}",
          f"**Corroborating detections ({inc['score']}):** " + ", ".join(inc["rules"]),
          f"**Evidence sources:** {', '.join(inc['sources'])}  ",
          f"**Related records:** {len(inc['eids'])}", "", "## Detections", ""]
    for r in inc["rules"]:
        L.append(f"- **{r}** — {RULES[r]}")
    L += ["", "## Reconstructed timeline (key records behind each detection)", "",
          "| Time (UTC, synchronized) | Detection | Source | Record |", "|---|---|---|---|"]
    rows = {}
    for a in sorted(inc["alerts"], key=lambda a: a["t0"]):
        sub = tl.loc[tl.index.isin(a["eids"])].sort_values("t").head(3)
        for i, r in sub.iterrows():
            rows.setdefault(i, (r, a["rule"].split("_")[0]))
    for i, (r, rule) in sorted(rows.items(), key=lambda kv: kv[1][0].t)[:max_rows]:
        L.append(f"| {_ts(r.t)} | {rule} | {r.source} | {_describe(r)} |")
    L += ["", f"Full timeline: {len(tl)} records across {len(inc['sources'])} sources."]
    if res.get("sync") is not None:
        L += ["", "## Clock synchronization applied", "", "| Clock domain | Offset (s) | Drift (s/h) |",
              "|---|---|---|"]
        for c, (a, b) in res["sync"].params.items():
            L.append(f"| {c} | {a:+.3f} | {b:+.4f} |")
    if res.get("stores"):
        L += ["", "## Chain of custody", "", "| Evidence file | Records | Checkpoints | Head (HMAC) | Verified |",
              "|---|---|---|---|---|"]
        for f, st in res["stores"].items():
            c = st.custody_record(case_id, "CLF pipeline")
            L.append(f"| {f} | {c['records']} | {c['checkpoints']} | `{c['head'][:16]}…` | "
                     f"{'yes' if c['verified'] else 'NO — ' + c['reason']} |")
    return "\n".join(L)
