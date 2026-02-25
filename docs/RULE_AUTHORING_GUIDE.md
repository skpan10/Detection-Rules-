# Detection Rule Authoring Guidelines

## Core Principle: Think Like an Attacker

Every rule in this repository is designed around an **attacker chain**, not individual events. A single event rarely means compromise — it's the *sequence* and *combination* of events that reveals attacker intent.

---

## The 3-Signal Rule

Before writing a rule, identify at least **3 signals** in the attacker's chain:

```
Signal 1 → Signal 2 → Signal 3
   ↑             ↑          ↑
Initial     Progression   Impact/
Access      of Attack     Goal
```

Only trigger your alert when **2 or more signals align** on the **same entity** (user, device, IP) within a **meaningful time window**.

---

## False Positive Reduction Checklist

Before finalizing a rule, ask yourself:

### ✅ Is this actually anomalous?
- [ ] Does this happen in normal IT operations? (software installs, patch management, admin tasks)
- [ ] Do help desk / service accounts perform this action routinely?
- [ ] Is there a scheduled task or automation that would explain this?

### ✅ Have I excluded known-good patterns?
- [ ] Known service account UPNs / naming patterns excluded
- [ ] Known RMM / patch management tool processes excluded
- [ ] Change window times excluded (if applicable)
- [ ] VPN IP ranges accounted for in geo-based rules

### ✅ Is the time window appropriate?
| Scenario | Recommended Window |
|----------|-------------------|
| Login → immediate execution | 15 minutes |
| Brute force → lateral movement | 2 hours |
| Risky login → defender alert | 4 hours |
| Full attack chain | 24 hours (hunting) |

### ✅ Does the threshold make sense?
- Typos cause 1-2 failed logins. Brute force causes 5-50+.
- Set your threshold **above** the noise floor for your environment.
- Use `percentile()` queries to find your baseline before hardcoding thresholds.

---

## Attacker Chain Reference

### Chain 1: Credential Compromise → Execution
```
Failed logins (T1110)
    └→ Successful login (T1078)
        └→ Recon commands (T1082, T1018)
            └→ Lateral movement (T1021)
                └→ Privilege escalation (T1078.002)
                    └→ Persistence (T1098, T1136)
```

### Chain 2: AiTM Phishing → BEC
```
Phishing email (T1566)
    └→ AiTM token capture (T1557)
        └→ Session replay from attacker IP (T1550.001)
            └→ Mail rule creation (T1114.003)
                └→ Financial fraud / data theft
```

### Chain 3: Endpoint Compromise → Cloud Pivot
```
Malware execution on endpoint (T1204)
    └→ Credential theft (T1003, T1555)
        └→ Azure AD login with stolen creds (T1078.004)
            └→ MFA bypass or SIM swap (T1621)
                └→ Cloud resource abuse (T1537)
```

---

## Rule Metadata Standard

Every rule file must include the following header comment block:

```kql
// ============================================================
// RULE: [Descriptive Name]
// ============================================================
// MITRE ATT&CK: [Tactic+Technique chain]
// Severity: Critical | High | Medium | Low
// Author: [Team/Person]
// Version: [X.Y]
//
// ATTACKER CHAIN LOGIC:
//   [Step-by-step description of what the attacker does]
//
// FALSE POSITIVE REDUCTION:
//   [List of specific FP scenarios and how they're handled]
// ============================================================
```

---

## Testing Your Rule

### 1. Baseline Query
Before deploying, run a 30-day baseline to understand alert volume:
```kql
// Add | summarize count() by bin(TimeGenerated, 1d) to your rule
// Target: < 5 alerts/day in a healthy environment
```

### 2. Validate Against Known TPs
- Red team exercises: ensure your rule fires
- Threat intel IOCs: replay known-bad events

### 3. Validate Against Known FPs
- IT admin doing their job: ensure your rule does NOT fire
- Patch Tuesday: run exclusions check

---

## Severity Guidelines

| Severity | Definition | Response SLA |
|----------|-----------|-------------|
| **Critical** | Confirmed multi-phase attack chain, likely active compromise | 15 minutes |
| **High** | Strong 2-signal correlation, probable compromise | 1 hour |
| **Medium** | Single suspicious signal + context, investigate | 4 hours |
| **Low** | Anomaly only, enrichment needed | 24 hours |

---

## Contributing

1. Fork the repo
2. Create a branch: `git checkout -b rule/description-of-rule`
3. Add your rule in the appropriate subfolder
4. Validate with `python scripts/validate_rules.py`
5. Submit a PR with: rule description, MITRE mapping, FP analysis, and test results
