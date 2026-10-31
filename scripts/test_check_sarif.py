import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from check_sarif import check_report


class SarifSecurityGateTests(unittest.TestCase):
    def report(self, severity="8.1", results=None):
        return {"version": "2.1.0", "runs": [{
            "tool": {"driver": {"rules": [{"id": "security/test", "properties": {"security-severity": severity}}]}},
            "results": [{"ruleId": "security/test"}] if results is None else results,
        }]}

    def check(self, report):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "test.sarif"
            path.write_text(json.dumps(report))
            return check_report(path)

    def test_high_and_critical_findings_block_even_when_suppressed(self):
        for severity in ["7.0", "8.1", "10"]:
            result = {"ruleId": "security/test", "suppressions": [{"kind": "inSource"}]}
            self.assertEqual(self.check(self.report(severity, [result])), ["security/test"])

    def test_medium_and_empty_reports_pass(self):
        self.assertEqual(self.check(self.report("6.9")), [])
        self.assertEqual(self.check(self.report(results=[])), [])

    def test_missing_rules_results_and_failed_analyzer_block(self):
        for report in [{}, {"version": "2.1.0", "runs": []}, self.report(results=[{"ruleId": "unknown"}])]:
            with self.assertRaises(ValueError):
                self.check(report)
        report = self.report()
        del report["runs"][0]["results"]
        with self.assertRaises(ValueError):
            self.check(report)
        report = self.report(results=[])
        report["runs"][0]["invocations"] = [{"executionSuccessful": False}]
        with self.assertRaises(ValueError):
            self.check(report)

    def test_extension_rules_preserve_severity_gate(self):
        report = self.report()
        run = report["runs"][0]
        run["tool"]["extensions"] = [{"name": "codeql/go-queries", "rules": run["tool"]["driver"].pop("rules")}]
        run["results"] = [{"rule": {"id": "security/test", "index": 0, "toolComponent": {"index": 0}}}]
        self.assertEqual(self.check(report), ["security/test"])
        run["results"][0]["rule"]["toolComponent"]["index"] = 1
        with self.assertRaises(ValueError):
            self.check(report)

    def test_invalid_scores_block(self):
        for severity in ["NaN", "Infinity", "-1", "11", "bad"]:
            with self.assertRaises(ValueError):
                self.check(self.report(severity))

    def test_review_requires_exact_source_function_and_origin(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "wire.zi"
            source.write_text("reviewed protocol source")
            artifact = root / "wire.zi.go"
            artifact.write_text("func WireDigest(value string) string {\nreturn sha256(value)\n}\nfunc WireAuth(password string) {\nWireDigest(password)\n}\n")
            physical = {"artifactLocation": {"uri": artifact.name}, "region": {"startLine": 2}}
            origin = {"artifactLocation": {"uri": artifact.name}, "region": {"startLine": 4}}
            result = {"ruleId": "security/test", "locations": [{"physicalLocation": physical}],
                      "codeFlows": [{"threadFlows": [{"locations": [{"location": {"physicalLocation": origin}}]}]}]}
            report = root / "test.sarif"
            report.write_text(json.dumps(self.report(results=[result])))
            reviews = [{"rule_id": "security/test", "artifact": artifact.name, "source": source.name,
                        "function": "WireDigest", "source_function": "WireAuth",
                        "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(), "reason": "protocol fixture"}]
            self.assertEqual(check_report(report, reviews, root), [])
            source.write_text("changed authentication source")
            self.assertEqual(check_report(report, reviews, root), ["security/test"])
            source.write_text("reviewed protocol source")
            for uri, line in [(artifact.name, 5), ("other.go", 2)]:
                physical.update(artifactLocation={"uri": uri}, region={"startLine": line})
                report.write_text(json.dumps(self.report(results=[result])))
                self.assertEqual(check_report(report, reviews, root), ["security/test"])
            physical.update(artifactLocation={"uri": artifact.name}, region={"startLine": 2})
            origin["region"]["startLine"] = 1
            report.write_text(json.dumps(self.report(results=[result])))
            self.assertEqual(check_report(report, reviews, root), ["security/test"])


if __name__ == "__main__":
    unittest.main()
