"""Privacy-aware analysis: keyed, consistent pseudonymization.

Personal identifiers (user names, client IP addresses, sessions, access keys)
are replaced with HMAC-SHA256 pseudonyms *after* coarse, non-identifying
attributes (ip_class, user_role) have been derived.  Pseudonyms are
consistent within a case, so correlation is unaffected, while only the key
holder (e.g. the case officer) can re-identify the entities of a confirmed
incident.  Infrastructure addresses (10.x tenant hosts) are kept so that
asset-level reasoning remains possible.
"""
import hashlib
import hmac

import pandas as pd

PII_COLS = ["user", "src_ip", "dst_ip", "session", "access_key"]


class Pseudonymizer:
    def __init__(self, key=b"case-key"):
        self.key = key
        self.reverse = {}

    def _p(self, prefix, v):
        if not isinstance(v, str) or v.startswith("10."):
            return v
        tok = prefix + hmac.new(self.key, v.encode(), hashlib.sha256).hexdigest()[:12]
        self.reverse[tok] = v
        return tok

    def transform(self, df):
        out = df.copy()
        cache = {}
        for c, pre in (("user", "U_"), ("src_ip", "IP_"), ("dst_ip", "IP_"), ("session", "S_"),
                       ("access_key", "K_")):
            vals = out[c].dropna().unique()
            mp = {v: self._p(pre, v) for v in vals}
            cache.update(mp)
            out[c] = out[c].map(lambda v, mp=mp: mp.get(v, v))
        # free-text fields may embed identities; keep only structured fields for analysis
        out.loc[out.source == "system", "msg"] = "[redacted]"
        out.loc[out.source == "application", "msg"] = out.loc[out.source == "application", "msg"] \
            .fillna("").str.replace(r"u\d{3}", "U_*", regex=True)
        return out

    def reidentify(self, token):
        return self.reverse.get(token, token)


def exposed_identifiers(df):
    """Number of distinct raw personal identifiers visible to an analyst."""
    n = 0
    for c in ("user", "session", "access_key"):
        s = df[c].dropna().astype(str)
        n += s[~s.str.startswith(("U_", "S_", "K_"))].nunique()
    ips = pd.concat([df.src_ip, df.dst_ip]).dropna().astype(str)
    n += ips[~ips.str.startswith(("IP_", "10."))].nunique()
    return int(n)
