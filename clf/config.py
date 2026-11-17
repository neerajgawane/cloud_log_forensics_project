"""Topology of the simulated cloud tenant used by every experiment.

The environment mirrors a small three-tier SaaS deployment on a public cloud:
two web servers behind a load balancer, one application server, an identity
provider (IdP), a database VM, VPC flow logging and a CloudTrail-style audit
trail.  Each log-producing host has its own (imperfect) clock.
"""

T0 = 1790812800.0  # 2026-10-01T00:00:00Z

HOSTS = {
    "web-1": "10.0.1.10",
    "web-2": "10.0.1.11",
    "app-1": "10.0.2.10",
    "idp-1": "10.0.3.10",
    "vm-db-1": "10.0.4.10",
    "jump-1": "10.0.9.5",
    "backup-1": "10.0.9.20",
    "scanner-1": "10.0.9.50",
}
IP_TO_HOST = {v: k for k, v in HOSTS.items()}

# Clock domains: one per log producer.  "cloudtrail" is the reference clock
# (provider-generated, NTP-disciplined), all others are skewed.
CLOCK_DOMAINS = ["web-1", "web-2", "app-1", "idp-1", "vpc", "vm-db-1", "cloudtrail"]
REFERENCE_CLOCK = "cloudtrail"

# Log files produced by the simulator: file -> (source category, clock domain)
LOG_FILES = {
    "web-1.access.log": ("web", "web-1"),
    "web-2.access.log": ("web", "web-2"),
    "app-1.jsonl": ("application", "app-1"),
    "idp-1.auth.log": ("security", "idp-1"),
    "vpc-flow.log": ("network", "vpc"),
    "cloudtrail.jsonl": ("audit", "cloudtrail"),
    "vm-db-1.syslog": ("system", "vm-db-1"),
}
SOURCE_CATEGORIES = ["web", "application", "security", "network", "audit", "system"]

# Destination ranges considered sanctioned for bulk egress (cloud object storage)
EGRESS_ALLOWLIST = ["52.216.", "52.217.", "52.218.", "52.219."]

ATTACK_STAGES = [
    "recon",
    "initial_access",
    "credential_access",
    "privilege_escalation",
    "lateral_movement",
    "exfiltration",
    "defense_evasion",
]


def is_internal(ip):
    return isinstance(ip, str) and ip.startswith("10.")


def is_allowlisted(ip):
    return isinstance(ip, str) and any(ip.startswith(p) for p in EGRESS_ALLOWLIST)
