# Forensic Incident Report — CASE-2026-001

**Incident window (reference clock, UTC):** 2026-10-01 01:24:14.107 → 2026-10-01 02:48:24.500
**Corroborating detections (8):** R1_web_404_burst, R2_sqli, R3_svc_login_external, R4_high_risk_iam, R5_web_to_db_ssh, R6_bulk_egress, R7_log_tampering, R8_bulk_object_read
**Evidence sources:** application, audit, network, security, system, web  
**Related records:** 198

## Detections

- **R1_web_404_burst** — ≥20 HTTP 404 responses from one client within 60 s
- **R2_sqli** — SQL-injection signature in request or DB syntax error in application
- **R3_svc_login_external** — Service/admin account authenticates from an external address
- **R4_high_risk_iam** — High-risk control-plane API call (key creation, policy attach, logging stop)
- **R5_web_to_db_ssh** — SSH from the web tier into the database tier
- **R6_bulk_egress** — ≥200 MB outbound to a non-allowlisted external destination
- **R7_log_tampering** — Command that clears or truncates logs / shell history
- **R8_bulk_object_read** — ≥15 object reads by one principal within 5 minutes

## Reconstructed timeline (key records behind each detection)

| Time (UTC, synchronized) | Detection | Source | Record |
|---|---|---|---|
| 2026-10-01 01:39:14.107 | R1 | web | 185.220.101.47 GET /cgi-bin/test.cgi -> 404 |
| 2026-10-01 01:39:16.366 | R1 | web | 185.220.101.47 GET /old/ -> 404 |
| 2026-10-01 01:39:17.255 | R1 | web | 185.220.101.47 GET /backup.zip -> 404 |
| 2026-10-01 01:45:02.727 | R2 | web | 185.220.101.47 GET /api/search?q=shoes' -> 500 |
| 2026-10-01 01:45:02.735 | R2 | application | db.error req=79b86ea3214ce4c2 {"err": "syntax error at or near \"'\""} |
| 2026-10-01 01:45:24.284 | R2 | web | 185.220.101.47 GET /api/search?q=shoes' OR 1=1-- -> 500 |
| 2026-10-01 01:45:24.297 | R2 | application | db.error req=457ea66e394f8f5e {"err": "syntax error at or near \"'\""} |
| 2026-10-01 01:45:35.646 | R2 | web | 185.220.101.47 GET /api/search?q=x' UNION SELECT null,null-- -> 200 |
| 2026-10-01 01:54:27.420 | R3 | security | LOGIN_FAILURE user=svc-backup from 185.220.101.47 |
| 2026-10-01 01:54:38.420 | R3 | security | LOGIN_FAILURE user=svc-backup from 185.220.101.47 |
| 2026-10-01 01:54:52.420 | R3 | security | LOGIN_SUCCESS user=svc-backup from 185.220.101.47 |
| 2026-10-01 01:57:49.500 | R4 | audit | CreateAccessKey by svc-backup (AKIABACKUP0000000001) from 185.220.101.47 |
| 2026-10-01 01:58:21.500 | R4 | audit | AttachUserPolicy by svc-backup (AKIABACKUP0000000001) from 185.220.101.47 |
| 2026-10-01 02:05:02.997 | R5 | network | 10.0.1.10:36740 -> 10.0.4.10:22 83,676 B |
| 2026-10-01 02:05:03.585 | R5 | system | SSH login dbadmin from 10.0.1.10 |
| 2026-10-01 02:06:24.994 | R6 | network | 10.0.4.10:41499 -> 45.137.21.9:443 284,221,666 B |
| 2026-10-01 02:06:54.500 | R8 | audit | GetObject by svc-backup (AKIA1DDFF5F0BD9CA773) from 185.220.101.47 |
| 2026-10-01 02:06:57.500 | R8 | audit | GetObject by svc-backup (AKIA1DDFF5F0BD9CA773) from 185.220.101.47 |
| 2026-10-01 02:07:03.500 | R8 | audit | GetObject by svc-backup (AKIA1DDFF5F0BD9CA773) from 185.220.101.47 |
| 2026-10-01 02:07:59.989 | R6 | network | 10.0.4.10:35600 -> 45.137.21.9:443 290,319,825 B |
| 2026-10-01 02:09:34.985 | R6 | network | 10.0.4.10:40227 -> 45.137.21.9:443 270,472,046 B |
| 2026-10-01 02:16:24.621 | R5 | system | SSH login dbadmin from 10.0.1.10 |
| 2026-10-01 02:16:24.968 | R5 | network | 10.0.1.10:38447 -> 10.0.4.10:22 26,293 B |
| 2026-10-01 02:16:34.621 | R7 | system | sudo dbadmin /usr/bin/truncate -s 0 /var/log/auth.log |
| 2026-10-01 02:16:40.621 | R7 | system | sudo dbadmin /usr/bin/rm -f /root/.bash_history /tmp/.c.dump /tmp/.c.tgz |
| 2026-10-01 02:18:24.500 | R4 | audit | StopLogging by svc-backup (AKIA1DDFF5F0BD9CA773) from 185.220.101.47 |

Full timeline: 198 records across 6 sources.

## Clock synchronization applied

| Clock domain | Offset (s) | Drift (s/h) |
|---|---|---|
| app-1 | +1.258 | +0.1474 |
| cloudtrail | -0.000 | +0.0000 |
| idp-1 | +0.407 | +0.0853 |
| vm-db-1 | +1.302 | -0.1863 |
| vpc | +0.176 | +0.1566 |
| web-1 | +0.553 | -0.0841 |
| web-2 | -1.831 | -0.1753 |

## Chain of custody

| Evidence file | Records | Checkpoints | Head (HMAC) | Verified |
|---|---|---|---|---|
| web-1.access.log | 10791 | 11 | `ae406b7004fc7740…` | yes |
| web-2.access.log | 10723 | 11 | `644b91f17536f8c3…` | yes |
| app-1.jsonl | 17164 | 18 | `1c25ea0891b7478d…` | yes |
| idp-1.auth.log | 737 | 1 | `2e2b7b7012e4e1c3…` | yes |
| vpc-flow.log | 22996 | 23 | `66d7976dfaff8e58…` | yes |
| cloudtrail.jsonl | 2327 | 3 | `971c5e3b159dc4e5…` | yes |
| vm-db-1.syslog | 842 | 1 | `e0fa365f98ebfea5…` | yes |