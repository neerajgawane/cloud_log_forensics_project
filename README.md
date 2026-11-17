# Cloud Log Forensics — implementation and evaluation

Implementation of the cloud log forensics (CLF) process described in
Khan et al., *"Cloud Log Forensics: Foundations, State of the Art, and Future Directions"*,
ACM Computing Surveys 49(1), 2016 (DOI 10.1145/2906149).

Course project, Cloud SRE and Security, IIIT Dharwad
(Akhilesh Ghadge 23BEC004 · Neeraj Gawane 23BEC031 · Chaitra V K 23BDS016).

## What it does

```
raw logs (6 formats, skewed clocks)
   │
   ├─ Collect / normalize   clf/normalize.py    6 parsers → 21-field common schema
   ├─ Preserve              clf/preservation.py HMAC hash chain + signed write-once checkpoints
   ├─ Synchronize           clf/sync.py         anchor matching → per-source offset + drift (WLS)
   ├─ Detect                clf/detect.py       8 rules → alerts with entities
   ├─ Correlate             clf/correlate.py    entity graph → corroborated incidents + timeline
   ├─ Privacy               clf/privacy.py      keyed pseudonymization (optional)
   └─ Report                clf/report.py       incident report + chain-of-custody table
```

`clf/generator.py` simulates a 3-tier cloud tenant (web ×2, app, IdP, DB VM, VPC flow logs,
CloudTrail) with per-host clock offset and drift, benign traffic with false-positive bait,
and a 7-stage intrusion (recon → SQL injection → credential use → IAM privilege escalation →
lateral SSH → exfiltration → log tampering). Ground truth is kept in a separate file.

## Run

```bash
pip install numpy pandas scipy matplotlib
python experiments/run_all.py          # all experiments (≈15 min on 2 vCPU); --quick for a smoke run
python experiments/make_figures.py     # figures/*.png
```

Single case:

```python
from clf.generator import Generator
from clf.pipeline import run
from clf.report import incident_report

Generator(seed=0).generate("data/demo")
res = run("data/demo")
print(res["metrics"])
print(incident_report(res))
```

## Experiments

| ID | Question | Output |
|----|----------|--------|
| E0 | End-to-end reconstruction accuracy | results/e0_baseline.json, results/incident_report.md |
| E1 | Tamper detection: plain / HMAC / chain / sealed chain | results/e1_integrity.json, fig2, fig3 |
| E2 | Clock synchronization under offset and drift | results/e2_sync.json, fig4, fig5 |
| E3 | Value of combining log categories; correlation ablation | results/e3_visibility.json, fig6 |
| E4 | Circular vs linear vs central sealed retention | results/e4_retention.json, fig7 |
| E5 | Privacy-preserving analysis | results/e5_privacy.json |
| E6 | Scalability | results/e6_scale.json, fig8 |
