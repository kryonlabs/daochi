#!/usr/bin/env python3
"""Fail the release gate on high severity or invalid SARIF security reports."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys


def function_lines(lines, name):
    start = next((index for index, line in enumerate(lines, 1)
                  if re.match(r"func " + re.escape(name) + r"\(", line)), None)
    if start is None:
        return None
    end = next((index for index in range(start, len(lines) + 1) if lines[index - 1] == "}"), None)
    return (start, end) if end is not None else None


def reviewed_finding(result, rule_id, reviews, source_root):
    if source_root is None:
        return False
    for review in reviews:
        if rule_id != review["rule_id"]:
            continue
        locations = result.get("locations", [])
        if len(locations) != 1:
            continue
        location = locations[0].get("physicalLocation", {})
        if location.get("artifactLocation", {}).get("uri") != review["artifact"]:
            continue
        source = (source_root / review["source"]).resolve()
        artifact = (source_root / review["artifact"]).resolve()
        if source_root.resolve() not in source.parents or source_root.resolve() not in artifact.parents:
            raise ValueError("security review path escapes the source tree")
        if source.stat().st_size > 1024 * 1024 or artifact.stat().st_size > 1024 * 1024:
            raise ValueError("reviewed security source exceeds size limit")
        if hashlib.sha256(source.read_bytes()).hexdigest() != review["source_sha256"]:
            continue
        lines = artifact.read_text().splitlines()
        bounds = function_lines(lines, review["function"])
        caller = function_lines(lines, review["source_function"])
        if bounds is None or caller is None:
            continue
        finding_line = location.get("region", {}).get("startLine")
        origins = []
        for flow in result.get("codeFlows", []):
            for thread in flow.get("threadFlows", []):
                steps = thread.get("locations", [])
                if steps:
                    origins.append(steps[0].get("location", {}).get("physicalLocation", {}))
        if not origins:
            continue
        if any(origin.get("artifactLocation", {}).get("uri") != review["artifact"] or
               type(origin.get("region", {}).get("startLine")) is not int or
               not caller[0] <= origin["region"]["startLine"] <= caller[1] for origin in origins):
            continue
        if type(finding_line) is int and bounds[0] <= finding_line <= bounds[1]:
            print("Reviewed protocol finding: " + review["function"] + ": " + review["reason"])
            return True
    return False


def check_report(path, reviews=(), source_root=None):
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
                if score >= 7 and not reviewed_finding(result, rule_id, reviews, source_root):
                    failures.append(rule_id or rule.get("id", "unknown"))
            elif result.get("level", rule.get("defaultConfiguration", {}).get("level")) == "error":
                failures.append(rule_id or rule.get("id", "unknown"))
    return failures


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--reviewed-policy", type=Path)
    args = parser.parse_args()
    try:
        reports = sorted(args.directory.glob("*.sarif"))
        if not reports:
            raise ValueError("no SARIF reports produced")
        reviews = []
        if args.reviewed_policy:
            if args.reviewed_policy.stat().st_size > 65536:
                raise ValueError("security review policy exceeds size limit")
            reviews = json.loads(args.reviewed_policy.read_text())
            if not isinstance(reviews, list):
                raise ValueError("invalid security review policy")
        source_root = Path(__file__).resolve().parents[1]
        failures = [finding for report in reports for finding in check_report(report, reviews, source_root)]
        if failures:
            raise ValueError("high severity findings: " + ", ".join(sorted(set(failures))))
    except (OSError, ValueError, TypeError, KeyError) as failure:
        print(f"security gate failed: {failure}", file=sys.stderr)
        return 1
    print("SARIF security gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
