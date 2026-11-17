"""Run every experiment of the paper and write results/*.json.

Usage:  python -m experiments.run_all [--quick]
"""
import json
import os
import sys
import time
import warnings

import numpy as np
import pandas as pd
from scipy.stats import kendalltau

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
warnings.filterwarnings("ignore")

from clf.generator import Generator  # noqa: E402
from clf.normalize import load_case, attach_ground_truth  # noqa: E402
from clf.pipeline import analyze, preserve_case  # noqa: E402
from clf.preservation import EvidenceStore, tamper, SCHEMES  # noqa: E402
from clf.privacy import exposed_identifiers  # noqa: E402
from clf.config import ATTACK_STAGES, LOG_FILES  # noqa: E402
from clf.report import incident_report  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "data")
RES = os.path.join(ROOT, "results")
QUICK = "--quick" in sys.argv
SEEDS = list(range(3)) if QUICK else list(range(10))


def case(name, **kw):
    d = os.path.join(DATA, name)
    if not os.path.exists(os.path.join(d, "_meta.json")):
        Generator(**kw).generate(d)
    return d


def load(d):
    return attach_ground_truth(load_case(d), d)


def save(name, obj):
    with open(os.path.join(RES, name + ".json"), "w") as fh:
        json.dump(obj, fh, indent=1, default=float)
    print(f"[saved] {name}")


def ms(xs):
    a = np.asarray(xs, float)
    return {"mean": float(a.mean()), "std": float(a.std()), "n": int(len(a))}


# ---------------------------------------------------------------- E0 baseline
def e0_baseline():
    d = case("main_s0", seed=0)
    df = load(d)
    res = analyze(df)
    res["stores"] = preserve_case(d)
    with open(os.path.join(RES, "incident_report.md"), "w") as fh:
        fh.write(incident_report(res))
    meta = json.load(open(os.path.join(d, "_meta.json")))
    stats = {"events": int(len(df)), "by_source": df.groupby("source").size().to_dict(),
             "attack_events": int((df.label == "attack").sum()),
             "attack_by_stage": df[df.label == "attack"].groupby("stage").size().to_dict(),
             "attack_by_source": df[df.label == "attack"].groupby("source").size().to_dict(),
             "alerts": [{"rule": a["rule"], "n": len(a["eids"]),
                         "attack": bool((df.loc[a["eids"], "label"] == "attack").all())} for a in res["alerts"]],
             "metrics": res["metrics"], "clock_true": meta["clock"],
             "clock_est": res["sync"].params, "edges": res["sync"].edges}
    # multi-seed main result
    rows = []
    for s in SEEDS:
        r = analyze(load(case(f"main_s{s}", seed=s)))["metrics"]
        rows.append(r)
    stats["multi_seed"] = {k: ms([r[k] for r in rows]) for k in
                           ("precision", "recall", "f1", "stage_coverage", "false_incidents", "incidents")}
    save("e0_baseline", stats)


# ---------------------------------------------------------------- E1 integrity
def e1_integrity():
    rng = np.random.default_rng(7)
    d = case("main_s0", seed=0)
    lines = []
    for f in ("cloudtrail.jsonl", "vm-db-1.syslog", "idp-1.auth.log"):
        lines += [ln.rstrip(b"\n") for ln in open(os.path.join(d, f), "rb")]
    lines = lines[:3000]
    attacks = ["modify", "delete", "insert", "reorder", "truncate"]
    trials = 60 if QUICK else 300
    table = {}
    for sch in SCHEMES:
        base = EvidenceStore(sch, b"k", checkpoint_every=100)
        base.extend(lines)
        if sch == "sealed":
            base.seal()
        table[sch] = {}
        for atk in attacks:
            det = 0
            for _ in range(trials):
                st = EvidenceStore(sch, b"k", 100)
                st.records = list(base.records)
                st.worm = list(base.worm)
                tamper(st, atk, rng)
                ok, _, _ = st.verify()
                det += (not ok)
            table[sch][atk] = det / trials
    # truncation between checkpoints: detection probability vs checkpoint interval
    trunc = {}
    for every in (10, 100, 1000):
        res = []
        full_st = EvidenceStore("sealed", b"k", every)
        full_st.extend(lines)
        for k in (1, 5, 20, 50, 200, 500):
            det = 0
            n_tr = 30 if QUICK else 100
            for _ in range(n_tr):
                # attacker strikes at a random moment between periodic seals (no final seal yet)
                n_live = int(rng.integers(1000, 3000))
                st = EvidenceStore("sealed", b"k", every)
                st.records = full_st.records[:n_live - k]
                st.worm = [c for c in full_st.worm if c[0] <= n_live]
                det += (not st.verify()[0])
            res.append({"k": k, "detect": det / n_tr})
        trunc[str(every)] = res
    # overhead
    over = {}
    big = lines * 10
    for sch in SCHEMES:
        st = EvidenceStore(sch, b"k", 1000)
        t = time.perf_counter(); st.extend(big); st.seal(); ta = time.perf_counter() - t
        t = time.perf_counter(); st.verify(); tv = time.perf_counter() - t
        over[sch] = {"append_rec_per_s": len(big) / ta, "verify_rec_per_s": len(big) / tv,
                     "tag_bytes_per_record": 64, "checkpoints": len(st.worm),
                     "raw_bytes_per_record": float(np.mean([len(x) for x in big]))}
    # localization: tampering pinpointed?
    loc_ok = 0
    for _ in range(100):
        st = EvidenceStore("sealed", b"k", 100); st.extend(lines); st.seal()
        i = tamper(st, "modify", rng)
        loc_ok += (st.verify()[1] == i)
    save("e1_integrity", {"detection": table, "truncation": trunc, "overhead": over,
                          "localization_accuracy": loc_ok / 100, "trials": trials,
                          "records": len(lines)})


# ---------------------------------------------------------------- E2 sync
def _order_metrics(df):
    a = df[df.label == "attack"].sort_values("true_ts")
    tt, te, src = a.true_ts.to_numpy(), a.t.to_numpy(), a.source.to_numpy()
    good = tot = 0
    for i in range(len(a)):
        m = (src[i + 1:] != src[i]) & (tt[i + 1:] - tt[i] > 1.0)
        tot += m.sum()
        good += (te[i + 1:][m] > te[i]).sum()
    tau = kendalltau(tt, te).statistic
    # fine-grained causality: application record must follow its web request
    w = df[df.source == "web"][["req_id", "t"]]
    ap = df[df.source == "application"].groupby("req_id").t.min()
    j = w.merge(ap.rename("ta"), left_on="req_id", right_index=True)
    viol = float((j.ta < j.t).mean()) if len(j) else float("nan")
    return {"pair_order_acc": good / tot if tot else float("nan"), "kendall_tau": float(tau),
            "causality_violation": viol,
            "mae_s": float((df.t - df.true_ts).abs().mean()),
            "p95_s": float((df.t - df.true_ts).abs().quantile(0.95))}


def e2_sync():
    out = {"offset_sweep": [], "drift_sweep": []}
    seeds = SEEDS[:3] if QUICK else SEEDS[:5]
    for off in (0.1, 0.5, 2, 10, 60, 300, 1800, 7200):
        for s in seeds:
            d = case(f"skew_o{off}_s{s}", seed=100 + s, max_offset=off, max_drift_ppm=50)
            df = load(d)
            for method in ("none", "offset", "drift"):
                r = analyze(df, sync=method)
                row = {"max_offset": off, "seed": s, "method": method, **_order_metrics(r["df"]),
                       **{k: r["metrics"][k] for k in ("f1", "recall", "precision", "stage_coverage")}}
                out["offset_sweep"].append(row)
        print("offset", off)
    for ppm in (0, 50, 200, 1000):
        for s in seeds:
            d = case(f"drift_p{ppm}_s{s}", seed=200 + s, max_offset=2, max_drift_ppm=ppm)
            df = load(d)
            for method in ("none", "offset", "drift"):
                r = analyze(df, sync=method)
                out["drift_sweep"].append({"max_drift_ppm": ppm, "seed": s, "method": method,
                                           **_order_metrics(r["df"]), "f1": r["metrics"]["f1"]})
        print("drift", ppm)
    save("e2_sync", out)


# ---------------------------------------------------------------- E3 visibility
SUBSETS = {
    "web": ["web"], "application": ["application"], "security": ["security"], "network": ["network"],
    "audit": ["audit"], "system": ["system"],
    "web+app": ["web", "application"], "network+security": ["network", "security"],
    "audit+security": ["audit", "security"],
    "all but audit": ["web", "application", "security", "network", "system"],
    "all but network": ["web", "application", "security", "audit", "system"],
    "all six": ["web", "application", "security", "network", "audit", "system"],
}


def e3_visibility():
    rows = []
    for s in SEEDS:
        d = case(f"main_s{s}", seed=s)
        full = load(d)
        n_att = int((full.label == "attack").sum())
        for name, srcs in SUBSETS.items():
            df = full[full.source.isin(srcs)].copy()
            for k in (1, 2):
                r = analyze(df, min_score=k)
                m = r["metrics"]
                rows.append({"subset": name, "seed": s, "min_score": k, "precision": m["precision"],
                             "recall_all": m["tp"] / n_att, "f1_all": (2 * m["precision"] * (m["tp"] / n_att) /
                                                                       (m["precision"] + m["tp"] / n_att)) if m["tp"] else 0.0,
                             "stage_coverage": m["stage_coverage"], "incidents": m["incidents"],
                             "false_incidents": m["false_incidents"],
                             "visible_attack_events": int((df.label == "attack").sum()) / n_att})
        # correlation design ablation on all sources
        for k in (1, 2, 3, 4):
            for exp in (True, False):
                r = analyze(full, min_score=k, expand_evidence=exp)
                m = r["metrics"]
                rows.append({"subset": f"ablation_k{k}_{'expand' if exp else 'alerts_only'}", "seed": s,
                             "min_score": k, "precision": m["precision"], "recall_all": m["recall"],
                             "f1_all": m["f1"], "stage_coverage": m["stage_coverage"],
                             "incidents": m["incidents"], "false_incidents": m["false_incidents"]})
        print("vis seed", s)
    save("e3_visibility", rows)


# ---------------------------------------------------------------- E4 retention
def e4_retention():
    rows = []
    seeds = SEEDS[:3] if QUICK else SEEDS[:6]
    for s in seeds:
        d = case(f"long_s{s}", seed=300 + s, hours=10, attack_frac=0.12)
        full = load(d)
        meta = json.load(open(os.path.join(d, "_meta.json")))
        t_end = meta["attack_end"]
        n_att = int((full.label == "attack").sum())
        # anti-forensics: attacker truncates the VM's local log at the evasion step
        trunc_t = full[(full.stage == "defense_evasion") & (full.source == "system")].true_ts.min()

        def evaluate_mask(mask, label, cap, delay):
            df = full[mask].copy()
            if not len(df):
                return
            r = analyze(df)
            m = r["metrics"]
            rows.append({"strategy": label, "capacity": cap, "delay_h": delay, "seed": s,
                         "retained_attack": int((df.label == "attack").sum()) / n_att,
                         "recall_all": m["tp"] / n_att, "stage_coverage": m["stage_coverage"],
                         "detected": int(m["tp"] > 0 and m["incidents"] > 0),
                         "precision": m["precision"]})

        for delay in (0, 1, 2, 4, 6, 8):
            t_inv = t_end + delay * 3600
            avail = full.true_ts <= t_inv
            wiped = (full.source == "system") & (full.true_ts < trunc_t)
            # centralized forwarding to sealed WORM store (proposed)
            evaluate_mask(avail, "central_sealed", None, delay)
            # local linear logs (unbounded) but host-local -> attacker wipes VM log
            evaluate_mask(avail & ~wiped, "local_linear", None, delay)
            for cap in (500, 2000, 5000, 20000, 50000):
                keep = pd.Series(False, index=full.index)
                for f in LOG_FILES:
                    idx = full.index[(full.file == f) & avail]
                    keep.loc[idx[-cap:]] = True
                evaluate_mask(keep & ~wiped, "local_circular", cap, delay)
        print("ret seed", s)
    save("e4_retention", rows)


# ---------------------------------------------------------------- E5 privacy
def e5_privacy():
    rows = []
    for s in SEEDS:
        df = load(case(f"main_s{s}", seed=s))
        for priv in (False, True):
            r = analyze(df, privacy=priv)
            m = r["metrics"]
            exposed = exposed_identifiers(r["df"])
            reid = 0
            if priv and r["incidents"]:
                ents = {e.split(":", 1)[1].split("@")[0] for a in r["incidents"][0]["alerts"] for e in a["entities"]}
                reid = sum(1 for e in ents if e.startswith(("U_", "IP_", "S_", "K_")))
            rows.append({"seed": s, "privacy": priv, "f1": m["f1"], "precision": m["precision"],
                         "recall": m["recall"], "exposed_identifiers": exposed,
                         "reidentified_for_case": reid, "time_s": sum(r["timings"].values())})
    save("e5_privacy", rows)


# ---------------------------------------------------------------- E6 scalability
def e6_scale():
    rows = []
    rates = (0.5, 1.5, 4) if QUICK else (0.5, 1.5, 4, 10, 20)
    for rate in rates:
        d = case(f"scale_r{rate}", seed=500, web_rate=rate)
        T = {}
        t = time.perf_counter(); stores = preserve_case(d); T["preserve"] = time.perf_counter() - t
        t = time.perf_counter(); df = load(d); T["collect_normalize"] = time.perf_counter() - t
        r = analyze(df, timings=T)
        n = len(df)
        rows.append({"web_rate": rate, "events": n, "mb": sum(os.path.getsize(os.path.join(d, f)) for f in LOG_FILES) / 1e6,
                     **{k: float(v) for k, v in T.items()}, "total_s": float(sum(T.values())),
                     "events_per_s": n / sum(T.values()), "f1": r["metrics"]["f1"]})
        print("scale", rate, n, sum(T.values()))
    save("e6_scale", rows)


if __name__ == "__main__":
    os.makedirs(RES, exist_ok=True)
    which = [a for a in sys.argv[1:] if not a.startswith("--")] or ["e0", "e1", "e2", "e3", "e4", "e5", "e6"]
    for w in which:
        t = time.time()
        globals()[{"e0": "e0_baseline", "e1": "e1_integrity", "e2": "e2_sync", "e3": "e3_visibility",
                   "e4": "e4_retention", "e5": "e5_privacy", "e6": "e6_scale"}[w]]()
        print(w, "done in", round(time.time() - t, 1), "s")
