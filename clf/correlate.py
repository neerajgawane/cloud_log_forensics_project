"""Analysis stage 2: cross-source correlation and incident reconstruction.

1. Alerts that share an entity (IP, user, access key, session, request id,
   host) and occur within `link_window` seconds of one another are merged with
   union-find into candidate incidents.
2. An incident is reported when it is corroborated by at least `min_score`
   distinct detection rules (multi-source corroboration suppresses the single
   noisy alerts that legitimate activity produces).
3. Evidence expansion: starting from the incident's indicators (external IPs,
   access keys, sessions, request ids, user@host), all related events inside the
   incident's time span are pulled in, with a second hop over request/session
   identifiers, yielding the reconstructed incident timeline.
"""
from collections import defaultdict

import numpy as np
import pandas as pd


class UF:
    def __init__(self, n):
        self.p = list(range(n))

    def f(self, x):
        while self.p[x] != x:
            self.p[x] = self.p[self.p[x]]
            x = self.p[x]
        return x

    def u(self, a, b):
        self.p[self.f(a)] = self.f(b)


def _gap(a, b):
    return max(0.0, max(a["t0"], b["t0"]) - min(a["t1"], b["t1"]))


def link_alerts(alerts, link_window=3600.0):
    uf = UF(len(alerts))
    by_ent = defaultdict(list)
    for i, a in enumerate(alerts):
        for e in a["entities"]:
            by_ent[e].append(i)
    for e, ids in by_ent.items():
        for x in range(len(ids)):
            for y in range(x + 1, len(ids)):
                if _gap(alerts[ids[x]], alerts[ids[y]]) <= link_window:
                    uf.u(ids[x], ids[y])
    groups = defaultdict(list)
    for i in range(len(alerts)):
        groups[uf.f(i)].append(i)
    return list(groups.values())


def expand(df, alerts, members, before=900.0, after=1800.0):
    ents = set()
    eids = set()
    for i in members:
        ents.update(alerts[i]["entities"])
        eids.update(alerts[i]["eids"])
    t_lo = min(alerts[i]["t0"] for i in members) - before
    t_hi = max(alerts[i]["t1"] for i in members) + after
    win = df[(df.t >= t_lo) & (df.t <= t_hi)]
    ext_ips = {e[3:] for e in ents if e.startswith("ip:") and not e[3:].startswith("10.")}
    aks = {e[3:] for e in ents if e.startswith("ak:")}
    sess = {e[5:] for e in ents if e.startswith("sess:")}
    reqs = {e[4:] for e in ents if e.startswith("req:")}
    hostusers = {e[5:].split("@")[0] for e in ents if e.startswith("user:") and "@" in e}
    m = (win.src_ip.isin(ext_ips) | win.dst_ip.isin(ext_ips) | win.access_key.isin(aks) |
         win.session.isin(sess) | win.req_id.isin(reqs) |
         ((win.source == "system") & win.user.isin(hostusers)))
    hit = win[m]
    # second hop over request ids and sessions discovered in hop 1
    reqs2 = set(hit.req_id.dropna()) | reqs
    aks2 = set(hit.access_key.dropna()) | aks
    m2 = win.req_id.isin(reqs2) | win.access_key.isin(aks2 - {None})
    eids.update(hit.index)
    eids.update(win[m2].index)
    return eids, (t_lo, t_hi)


def correlate(df, alerts, link_window=3600.0, min_score=2):
    groups = link_alerts(alerts, link_window)
    incidents = []
    for g in groups:
        rules = sorted({alerts[i]["rule"] for i in g})
        if len(rules) < min_score:
            continue
        eids, span = expand(df, alerts, g)
        sub = df.loc[sorted(eids)].sort_values("t")
        incidents.append({"alerts": [alerts[i] for i in g], "rules": rules, "score": len(rules),
                          "eids": set(eids), "span": span, "sources": sorted(sub.source.unique()),
                          "timeline": sub})
    incidents.sort(key=lambda x: -x["score"])
    return incidents


def evaluate(df, incidents, stages):
    """Event-level P/R/F1 against ground-truth labels + stage coverage."""
    pred = set()
    for inc in incidents:
        pred |= inc["eids"]
    truth = set(df.index[df.label == "attack"])
    tp = len(pred & truth)
    fp = len(pred - truth)
    fn = len(truth - pred)
    P = tp / (tp + fp) if tp + fp else 0.0
    R = tp / (tp + fn) if tp + fn else 0.0
    F = 2 * P * R / (P + R) if P + R else 0.0
    covered = set(df.loc[sorted(pred & truth), "stage"]) if tp else set()
    false_inc = sum(1 for inc in incidents if not (inc["eids"] & truth))
    return {"precision": P, "recall": R, "f1": F, "tp": tp, "fp": fp, "fn": fn,
            "stage_coverage": len(covered & set(stages)) / len(stages),
            "stages_found": sorted(covered), "incidents": len(incidents), "false_incidents": false_inc}
