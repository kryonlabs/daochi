#!/usr/bin/env python3
"""Fail the release gate on high severity or invalid SARIF security reports."""

import argparse
import json
from pathlib import Path
import sys


def check_report(path):
    if path.stat().st_size > 16 * 1024 * 1024:
        raise ValueError(f"SARIF report exceeds the review limit: {path.name}")
    with path.open() as stream:
        report = json.load(stream)
    if report.get("version") != "2.1.0" or not isinstance(report.get("runs"), list) or not report["runs"]:
        raise ValueError(f"invalid SARIF report: {path.name}")
    failures = []
    for run in report["runs"]:
        for invocation in run.get("invocations", []):
            if invocation.get("executionSuccessful") is False:
                raise ValueError(f"SARIF analyzer failed: {path.name}")
        tool = run.get("tool", {})
        if not isinstance(run.get("results"), list):
            raise ValueError(f"SARIF results missing: {path.name}")
        for result in run["results"]:
            reference = result.get("rule", {})
            component = reference.get("toolComponent", {})
            selected = tool.get("driver", {})
            if component:
                extensions = tool.get("extensions", [])
                index = component.get("index")
                if type(index) is not int or not 0 <= index < len(extensions):
                    raise ValueError(f"invalid SARIF tool component: {path.name}")
                selected = extensions[index]
                for key in ("name", "guid"):
                    if key in component and component[key] != selected.get(key):
                        raise ValueError(f"mismatched SARIF tool component: {path.name}")
            rules = selected.get("rules", [])
            by_id = {rule["id"]: rule for rule in rules}
            rule_id = reference.get("id", result.get("ruleId", ""))
            rule = by_id.get(rule_id)
            if rule is None and type(reference.get("index", result.get("ruleIndex"))) is int:
                index = reference.get("index", result.get("ruleIndex"))
                if 0 <= index < len(rules):
                    rule = rules[index]
            if rule is None:
                raise ValueError(f"SARIF finding has no rule: {path.name}")
            severity = rule.get("properties", {}).get("security-severity")
            if severity is not None:
                score = float(severity)
                if not 0 <= score <= 10:
                    raise ValueError(f"invalid SARIF severity: {rule_id}")
                if score >= 7:
                    failures.append(rule_id or rule.get("id", "unknown"))
            elif result.get("level", rule.get("defaultConfiguration", {}).get("level")) == "error":
                failures.append(rule_id or rule.get("id", "unknown"))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    try:
        reports = sorted(args.directory.glob("*.sarif"))
        if not reports:
            raise ValueError("no SARIF reports produced")
        failures = [finding for report in reports for finding in check_report(report)]
        if failures:
            raise ValueError("high severity findings: " + ", ".join(sorted(set(failures))))
    except (OSError, ValueError, TypeError, KeyError) as failure:
        print(f"security gate failed: {failure}", file=sys.stderr)
        return 1
    print("SARIF security gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
