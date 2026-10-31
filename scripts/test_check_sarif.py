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

    def test_invalid_scores_block(self):
        for severity in ["NaN", "Infinity", "-1", "11", "bad"]:
            with self.assertRaises(ValueError):
                self.check(self.report(severity))


if __name__ == "__main__":
    unittest.main()
