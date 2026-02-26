#!/usr/bin/env python3
"""
validate_rules.py - KQL rule validation script
Warnings are informational only - only critical errors cause failure.
"""

import os
import sys
import re
import argparse
from pathlib import Path

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}


def validate_rule(filepath: str) -> tuple:
    errors = []
    warnings = []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception as e:
        errors.append(f"Could not read file: {e}")
        return errors, warnings

    recommended_fields = [
        "RULE:", "MITRE ATT&CK:", "Severity:",
        "ATTACKER CHAIN LOGIC:", "FALSE POSITIVE REDUCTION:"
    ]
    for field in recommended_fields:
        if field not in content:
            warnings.append(f"Missing recommended header: '{field}'")

    severity_match = re.search(r"// Severity:\s*(\w+)", content)
    if severity_match:
        severity = severity_match.group(1)
        if severity not in VALID_SEVERITIES:
            warnings.append(f"Unusual severity '{severity}'")

    return errors, warnings


def main():
    parser = argparse.ArgumentParser(description="Validate KQL detection rules")
    parser.add_argument("--rule", help="Path to a single .kql rule file")
    parser.add_argument("--dir", help="Directory to validate", default="rules/")
    args = parser.parse_args()

    total_errors = 0
    total_warnings = 0

    print("\n" + "="*50)
    print("  DETECTION RULES VALIDATOR")
    print("="*50)

    if args.rule:
        files = [Path(args.rule)]
    else:
        files = list(Path(args.dir).rglob("*.kql"))

    if not files:
        print(f"  No .kql files found.")
        print("  PASSED")
        sys.exit(0)

    for kql_file in files:
        errors, warnings = validate_rule(str(kql_file))
        name = os.path.basename(str(kql_file))
        if not errors and not warnings:
            print(f"  PASS: {name}")
        else:
            print(f"  FILE: {name}")
            for w in warnings:
                print(f"    WARNING: {w}")
                total_warnings += 1
            for e in errors:
                print(f"    ERROR: {e}")
                total_errors += 1

    print(f"\n  Files: {len(files)} | Errors: {total_errors} | Warnings: {total_warnings}")

    if total_errors > 0:
        print("  FAILED")
        sys.exit(1)
    else:
        print("  PASSED")
        sys.exit(0)


if __name__ == "__main__":
    main()
