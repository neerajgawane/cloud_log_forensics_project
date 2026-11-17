"""End-to-end Cloud Log Forensics pipeline (Detect -> Collect -> Preserve ->
Synchronize/Correlate -> Analyze -> Report), following the forensic process
of Khan et al. (ACM CSUR 2016)."""
import os
import time

from .config import LOG_FILES, ATTACK_STAGES
from .normalize import load_case, attach_ground_truth
from .preservation import EvidenceStore
from .sync import ClockSynchronizer, no_sync
from .detect import detect, add_attributes
from .correlate import correlate, evaluate
from .privacy import Pseudonymizer


def preserve_case(case_dir, scheme="sealed", every=1000, key=b"forensic-key"):
    stores = {}
    for fname in LOG_FILES:
        p = os.path.join(case_dir, fname)
        if not os.path.exists(p):
            continue
        st = EvidenceStore(scheme, key, every)
        with open(p, "rb") as fh:
            for ln in fh:
                st.append(ln.rstrip(b"\n"))
        st.seal()
        stores[fname] = st
    return stores


def analyze(df, sync="drift", privacy=False, min_score=2, link_window=3600.0, expand_evidence=True,
            timings=None):
    """Synchronize -> (pseudonymize) -> detect -> correlate on a normalized frame."""
    T = timings if timings is not None else {}
    t = time.perf_counter()
    syncer = None
    if sync in ("drift", "offset"):
        syncer = ClockSynchronizer(drift=(sync == "drift")).fit(df)
        df = syncer.transform(df)
    else:
        df = no_sync(df)
    T["synchronize"] = time.perf_counter() - t
    df = add_attributes(df)
    pz = None
    if privacy:
        pz = Pseudonymizer()
        df = pz.transform(df)
    t = time.perf_counter()
    alerts = detect(df)
    T["detect"] = time.perf_counter() - t
    t = time.perf_counter()
    incidents = correlate(df, alerts, link_window=link_window, min_score=min_score)
    if not expand_evidence:
        for inc in incidents:
            inc["eids"] = set(e for a in inc["alerts"] for e in a["eids"])
    T["correlate"] = time.perf_counter() - t
    res = {"df": df, "alerts": alerts, "incidents": incidents, "sync": syncer, "pseudonymizer": pz,
           "timings": T}
    if "label" in df.columns:
        res["metrics"] = evaluate(df, incidents, ATTACK_STAGES)
    return res


def run(case_dir, sources=None, preserve=True, with_truth=True, **kw):
    T = {}
    t = time.perf_counter()
    stores = preserve_case(case_dir) if preserve else {}
    T["preserve"] = time.perf_counter() - t
    t = time.perf_counter()
    df = load_case(case_dir, sources)
    if with_truth:
        df = attach_ground_truth(df, case_dir)
    T["collect_normalize"] = time.perf_counter() - t
    res = analyze(df, timings=T, **kw)
    res["stores"] = stores
    return res
