# 🛡️ Detection Rules Repository

> Threat detection rules for Microsoft Defender + Azure AD environments, built around attacker chain logic to minimize false positives.

## 📁 Repository Structure

```
detection-rules-repo/
├── rules/
│   ├── correlation/        # Multi-signal correlation rules (failed logins + process spawns)
│   ├── defender_azure/     # Combined Defender + Azure AD rules
│   └── hunting/            # Proactive threat hunting queries
├── docs/                   # Rule authoring guidelines & attacker chain maps
├── scripts/                # Validation & deployment helpers
└── tests/                  # Unit tests for rule logic
```

## 🧠 Design Philosophy

Rules in this repo are designed by **thinking like an attacker**, not just matching individual events. Each rule targets a **phase in the attack chain** and requires multiple signals to fire, reducing alert fatigue.

### The 3 Pillars

| Pillar | What it means |
|--------|--------------|
| **Correlate** | Multiple events must align in time + context (user, host, IP) |
| **Combine** | Cross-product signals (Defender EDR + Azure AD Identity) |
| **Reduce** | Logical exclusions based on normal attacker behavior vs. benign noise |

## 🚀 Quick Start

### Prerequisites
- Microsoft Sentinel workspace
- Log Analytics connected to: Microsoft Defender for Endpoint, Azure AD Sign-in Logs, Azure AD Audit Logs

### Deploy a Rule
```bash
# Validate rule syntax
python scripts/validate_rules.py --rule rules/correlation/failed_login_process_spawn.kql

# Deploy to Sentinel
python scripts/deploy_rule.py --rule rules/correlation/failed_login_process_spawn.kql --workspace <workspace-id>
```

## 📖 Rule Index

### Correlation Rules
| Rule | MITRE Tactic | Severity |
|------|-------------|----------|
| [Failed Login + Process Spawn](rules/correlation/failed_login_process_spawn.kql) | Initial Access → Execution | High |
| [Brute Force + Lateral Movement](rules/correlation/brute_force_lateral_movement.kql) | Credential Access → Lateral Movement | Critical |
| [MFA Bypass + Suspicious Session](rules/correlation/mfa_bypass_suspicious_session.kql) | Initial Access | High |

### Defender + Azure AD Combined Rules
| Rule | MITRE Tactic | Severity |
|------|-------------|----------|
| [Impossible Travel + Malware Alert](rules/defender_azure/impossible_travel_malware.kql) | Initial Access | Critical |
| [Azure AD Risky Sign-in + EDR Alert](rules/defender_azure/risky_signin_edr_alert.kql) | Initial Access → Execution | High |
| [Privileged Account Abuse Chain](rules/defender_azure/privileged_account_abuse.kql) | Privilege Escalation | Critical |

### Hunting Queries
| Query | Purpose |
|-------|---------|
| [Living-off-the-Land Baseline](rules/hunting/lolbin_baseline.kql) | Detect LOLBIN abuse post-login failure |
| [Token Theft Indicators](rules/hunting/token_theft_indicators.kql) | OAuth/SAML token abuse hunting |

## 🔗 Contributing
See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for rule authoring standards.

## 📄 License
MIT
