#!/usr/bin/env python3
"""
validate_rules.py - Basic KQL rule validation script
Checks for required metadata headers and common mistakes
"""

import os
import sys
import re
import argparse
from pathlib import Path

REQUIRED_HEADER_FIELDS = ["RULE:", "MITRE ATT&CK:", "Severity:", "ATTACKER CHAIN LOGIC:", "FALSE POSITIVE REDUCTION:"]
VALID_SEVERITIES = {"Critical", "High", "Medium", "Low"}

def validate_rule(filepath: str) -> list[str]:
    """Returns list of validation errors for a KQL rule file."""
    errors = []
    
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
    
    # Check required header fields
    for field in REQUIRED_HEADER_FIELDS:
        if field not in content:
            errors.append(f"Missing required header field: '{field}'")
    
    # Check severity is valid
    severity_match = re.search(r"// Severity:\s*(\w+)", content)
    if severity_match:
        severity = severity_match.group(1)
        if severity not in VALID_SEVERITIES:
            errors.append(f"Invalid severity '{severity}'. Must be one of: {VALID_SEVERITIES}")
    
    # Check for hardcoded tenant/domain values that should be parameterized
    if re.search(r"@[a-zA-Z0-9-]+\.(com|org|net|io)\b", content):
        if "yourdomain.com" not in content:
            errors.append("WARNING: Possible hardcoded domain found. Use 'yourdomain.com' placeholder.")
            total_warnings += 1
            continue
    
    # Check for time window definition
    if "let LookbackWindow" not in content and "let HuntingWindow" not in content:
        errors.append("WARNING: No LookbackWindow or HuntingWindow defined. Add explicit time bounds.")
    
    # Check for order by (good practice for readability)
    if "| order by" not in content.lower():
        errors.append("WARNING: No 'order by' clause. Add one for consistent output.")
    
    return errors


def validate_directory(directory: str) -> dict[str, list[str]]:
    """Validate all .kql files in a directory recursively."""
    results = {}
    for kql_file in Path(directory).rglob("*.kql"):
        errors = validate_rule(str(kql_file))
        results[str(kql_file)] = errors
    return results


def main():
    parser = argparse.ArgumentParser(description="Validate KQL detection rules")
    parser.add_argument("--rule", help="Path to a single .kql rule file")
    parser.add_argument("--dir", help="Directory to validate all .kql files", default="rules/")
    args = parser.parse_args()
    
    total_errors = 0
    total_warnings = 0
    
    if args.rule:
        errors = validate_rule(args.rule)
        print(f"\n📋 Validating: {args.rule}")
        if not errors:
            print("  ✅ All checks passed!")
        else:
            for e in errors:
                prefix = "  ⚠️ " if e.startswith("WARNING") else "  ❌ "
                print(f"{prefix}{e}")
                if e.startswith("WARNING"):
                    total_warnings += 1
                else:
                    total_errors += 1
    else:
        results = validate_directory(args.dir)
        for filepath, errors in results.items():
            print(f"\n📋 {filepath}")
            if not errors:
                print("  ✅ All checks passed!")
            else:
                for e in errors:
                    prefix = "  ⚠️ " if e.startswith("WARNING") else "  ❌ "
                    print(f"{prefix}{e}")
                    if e.startswith("WARNING"):
                        total_warnings += 1
                    else:
                        total_errors += 1
    
    print(f"\n{'='*50}")
    print(f"Summary: {total_errors} errors, {total_warnings} warnings")
    
    if total_errors > 0:
        sys.exit(1)
    else:
        print("\n✅ All rules passed validation!")
        sys.exit(0)


if __name__ == "__main__":
    main()
