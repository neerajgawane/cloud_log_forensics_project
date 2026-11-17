"""Cross-source timestamp synchronization.

Every clock domain c has an unknown affine error  e_c(t) = a_c + b_c (t - T0)
relative to the reference clock (the provider audit trail).  Records that
describe the *same physical interaction* in two domains ("anchors") give noisy
measurements of e_v - e_u:

  web  <-> application : shared request id
  application <-> audit : shared cloud API request id
  network <-> web / security / system : same (src_ip, src_port, dst_port) 5-tuple

For every pair of domains we robustly fit an affine model to the anchor
differences (iteratively trimmed least squares), then solve a weighted global
least-squares problem over the domain graph with the reference fixed at zero.
Corrected time:  t_hat = ts - e_c(ts).
"""
import numpy as np
import pandas as pd

from .config import T0, REFERENCE_CLOCK


def find_anchors(df):
    """Return DataFrame of anchor pairs: clock_u, clock_v, ts_u, ts_v, lag (expected v-u)."""
    out = []
    web = df[df.source == "web"]
    app = df[df.source == "application"]
    if len(web) and len(app):
        a = app.groupby("req_id").ts.min().rename("ts_v")
        m = web[["req_id", "clock", "ts"]].merge(a, left_on="req_id", right_index=True)
        out.append(pd.DataFrame({"u": m.clock, "v": "app-1", "ts_u": m.ts, "ts_v": m.ts_v, "lag": 0.022}))
    aud = df[(df.source == "audit") & df.aws_req.notna()]
    if len(app) and len(aud):
        ap = app[app.aws_req.notna()][["aws_req", "ts", "clock"]]
        m = ap.merge(aud[["aws_req", "ts", "clock"]], on="aws_req", suffixes=("_u", "_v"))
        out.append(pd.DataFrame({"u": m.clock_u, "v": m.clock_v, "ts_u": m.ts_u, "ts_v": m.ts_v,
                                 "lag": 0.09 - 0.02}))
    net = df[df.source == "network"][["src_ip", "src_port", "dst_port", "ts", "clock"]].dropna()
    for src, lag in (("web", 0.0425), ("security", 0.105), ("system", 0.011)):
        s = df[(df.source == src) & df.src_port.notna()][["src_ip", "src_port", "dst_port", "ts", "clock"]]
        if not len(s) or not len(net):
            continue
        m = net.merge(s, on=["src_ip", "src_port", "dst_port"], suffixes=("_u", "_v"))
        if not len(m):
            continue
        out.append(pd.DataFrame({"u": m.clock_u, "v": m.clock_v, "ts_u": m.ts_u, "ts_v": m.ts_v,
                                 "lag": lag}))
    if not out:
        return pd.DataFrame(columns=["u", "v", "ts_u", "ts_v", "lag"])
    return pd.concat(out, ignore_index=True)


def _robust_affine(t, d, drift=True, iters=4):
    x = (t - T0) / 3600.0  # hours
    keep = np.ones(len(d), bool)
    for _ in range(iters):
        if drift and keep.sum() >= 6 and np.ptp(x[keep]) > 0.25:
            A = np.c_[np.ones(keep.sum()), x[keep]]
            coef, *_ = np.linalg.lstsq(A, d[keep], rcond=None)
        else:
            coef = np.array([np.median(d[keep]), 0.0])
        res = d - (coef[0] + coef[1] * x)
        mad = np.median(np.abs(res[keep] - np.median(res[keep]))) + 1e-6
        new_keep = np.abs(res) < 3.5 * 1.4826 * mad + 0.05
        if new_keep.sum() < max(3, 0.2 * len(d)):
            break
        keep = new_keep
    res = d - (coef[0] + coef[1] * x)
    var = np.var(res[keep]) + 1e-6
    return coef, var, int(keep.sum())


class ClockSynchronizer:
    def __init__(self, drift=True, reference=REFERENCE_CLOCK):
        self.drift = drift
        self.ref = reference
        self.params = {}
        self.edges = []

    def fit(self, df, passes=2):
        """Two passes: the second regresses anchor differences on the *corrected*
        time of the first pass, so large offsets do not bias the drift estimate."""
        anchors = find_anchors(df)
        self.params = {}
        for _ in range(passes):
            self._fit_once(df, anchors)
        self.n_anchors = int(len(anchors))
        return self

    def _correct(self, clock, ts):
        a, b = self.params.get(clock, (0.0, 0.0))
        return T0 + (ts - T0 - a) / (1.0 + b / 3600.0)

    def _fit_once(self, df, anchors):
        clocks = sorted(set(df.clock.unique()))
        if self.ref not in clocks:
            # fall back to the most-connected clock as reference
            self.ref = clocks[0]
        idx = {c: i for i, c in enumerate(clocks)}
        rows, rhs, w = [], [], []
        self.edges = []
        for (u, v), g in anchors.groupby(["u", "v"]):
            if u == v or len(g) < 3:
                continue
            d = (g.ts_v - g.ts_u - g.lag).to_numpy(dtype=float)
            ok = np.isfinite(d)
            if ok.sum() < 3:
                continue
            g = g[ok]; d = d[ok]
            tu = np.array([self._correct(u, x) for x in g.ts_u.to_numpy(dtype=float)]) if self.params \
                else g.ts_u.to_numpy(dtype=float)
            coef, var, n = _robust_affine(tu, d, self.drift)
            self.edges.append(dict(u=u, v=v, n=n, a=coef[0], b=coef[1], sd=float(np.sqrt(var))))
            wt = n / var
            for k in range(2):  # intercept and slope equations
                r = np.zeros(2 * len(clocks))
                r[2 * idx[v] + k] = 1
                r[2 * idx[u] + k] = -1
                rows.append(r); rhs.append(coef[k]); w.append(wt if k == 0 else wt * 0.25)
        # pin the reference
        for k in range(2):
            r = np.zeros(2 * len(clocks)); r[2 * idx[self.ref] + k] = 1
            rows.append(r); rhs.append(0.0); w.append(1e6)
        # weak prior (zero error) keeps disconnected clocks defined
        for c in clocks:
            for k in range(2):
                r = np.zeros(2 * len(clocks)); r[2 * idx[c] + k] = 1
                rows.append(r); rhs.append(0.0); w.append(1e-6)
        A = np.array(rows) * np.sqrt(np.array(w))[:, None]
        b = np.array(rhs) * np.sqrt(np.array(w))
        sol, *_ = np.linalg.lstsq(A, b, rcond=None)
        self.params = {c: (float(sol[2 * idx[c]]), float(sol[2 * idx[c] + 1])) for c in clocks}

    def transform(self, df):
        out = df.copy()
        a = out.clock.map(lambda c: self.params.get(c, (0.0, 0.0))[0])
        b = out.clock.map(lambda c: self.params.get(c, (0.0, 0.0))[1])
        # exact inverse of  obs = t + a + b (t - T0)/3600
        out["t"] = T0 + (out.ts - T0 - a) / (1.0 + b / 3600.0)
        return out


def no_sync(df):
    out = df.copy()
    out["t"] = out.ts
    return out
