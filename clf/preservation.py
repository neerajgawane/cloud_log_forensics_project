"""Evidence preservation: tamper-evident log storage and verification.

Implements the integrity / authenticity / chain-of-custody requirements that
Khan et al. identify for cloud log forensics.  Four schemes are provided so
they can be compared experimentally against a privileged insider who can
rewrite the log store but does not hold the forensic key:

  plain     - SHA-256 digest per record stored next to the record
  hmac      - keyed HMAC-SHA256 per record (no ordering information)
  chain     - forward HMAC hash chain  h_i = HMAC(k, h_{i-1} || i || r_i)
  sealed    - hash chain + periodic checkpoints (index, count, head) signed and
              written to a write-once (WORM) store outside the attacker's reach

The `sealed` scheme is the one used by the pipeline.
"""
import hashlib
import hmac
import time

SCHEMES = ["plain", "hmac", "chain", "sealed"]


def _h(b):
    return hashlib.sha256(b).hexdigest()


def _mac(key, b):
    return hmac.new(key, b, hashlib.sha256).hexdigest()


class EvidenceStore:
    def __init__(self, scheme="sealed", key=b"forensic-key", checkpoint_every=1000):
        assert scheme in SCHEMES
        self.scheme = scheme
        self.key = key
        self.every = checkpoint_every
        self.records = []     # (record bytes, tag) -- attacker-writable
        self.worm = []        # sealed checkpoints -- attacker cannot modify
        self._head = "0" * 64

    def append(self, rec: bytes):
        i = len(self.records)
        if self.scheme == "plain":
            tag = _h(rec)
        elif self.scheme == "hmac":
            tag = _mac(self.key, rec)
        else:
            tag = _mac(self.key, self._head.encode() + str(i).encode() + b"|" + rec)
            self._head = tag
        self.records.append((rec, tag))
        if self.scheme == "sealed" and (i + 1) % self.every == 0:
            self.seal()

    def seal(self):
        n = len(self.records)
        if self.worm and self.worm[-1][0] == n:
            return
        sig = _mac(self.key, f"{n}|{self._head}".encode())
        self.worm.append((n, self._head, sig))

    def extend(self, recs):
        for r in recs:
            self.append(r)

    # ------------------------------------------------------------ verify
    def verify(self):
        """Return (ok, first_bad_index or None, reason)."""
        recs = self.records
        if self.scheme == "plain":
            for i, (r, t) in enumerate(recs):
                if _h(r) != t:
                    return False, i, "digest mismatch"
            return True, None, ""
        if self.scheme == "hmac":
            for i, (r, t) in enumerate(recs):
                if _mac(self.key, r) != t:
                    return False, i, "mac mismatch"
            return True, None, ""
        head = "0" * 64
        heads = {}
        for i, (r, t) in enumerate(recs):
            exp = _mac(self.key, head.encode() + str(i).encode() + b"|" + r)
            if exp != t:
                return False, i, "chain break"
            head = t
            heads[i + 1] = head
        if self.scheme == "sealed":
            for n, h, sig in self.worm:
                if _mac(self.key, f"{n}|{h}".encode()) != sig:
                    return False, None, "checkpoint signature invalid"
                if n > len(recs):
                    return False, len(recs), f"truncation: {n - len(recs)}+ records missing vs checkpoint"
                if heads.get(n) != h:
                    return False, n, "checkpoint head mismatch"
        return True, None, ""

    def custody_record(self, case_id, custodian):
        ok, idx, why = self.verify()
        return {"case": case_id, "custodian": custodian, "scheme": self.scheme,
                "records": len(self.records), "checkpoints": len(self.worm),
                "head": self.records[-1][1] if self.records else None,
                "verified": ok, "first_bad_index": idx, "reason": why,
                "verified_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}


# --------------------------------------------------------- insider attacks
def _recompute_tail(store, start):
    """What an attacker without the key can do: recompute *unkeyed* digests only."""
    if store.scheme == "plain":
        store.records = [(r, _h(r)) for r, _ in store.records]


def tamper(store, kind, rng):
    """Apply an insider tampering action in place. Returns affected index."""
    n = len(store.records)
    if kind == "modify":
        i = int(rng.integers(0, n))
        r, t = store.records[i]
        store.records[i] = (r.replace(b"185.", b"10.").replace(b"LOGIN", b"LOGIN ") + b" ", t)
    elif kind == "delete":
        i = int(rng.integers(0, n))
        del store.records[i]
    elif kind == "insert":
        i = int(rng.integers(0, n))
        fake = b"forged benign record"
        # attacker copies a neighbouring tag (cannot compute a valid MAC)
        store.records.insert(i, (fake, store.records[i][1]))
    elif kind == "reorder":
        i = int(rng.integers(0, n - 1))
        store.records[i], store.records[i + 1] = store.records[i + 1], store.records[i]
    elif kind == "truncate":
        k = int(rng.integers(1, max(2, n // 10)))
        i = n - k
        store.records = store.records[:i]
    else:
        raise ValueError(kind)
    _recompute_tail(store, i)
    return i
