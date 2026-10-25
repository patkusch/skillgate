import json
import unittest
from pathlib import Path

from skillgate import report
from skillgate.scan import scan_skill

FIX = Path(__file__).parent.parent / "fixtures"


class PlainText(unittest.TestCase):
    def test_a_clean_skill_says_ok_and_that_it_only_holds_instructions(self):
        out = report.text(scan_skill(FIX / "clean"))
        self.assertIn(report.VERDICT_TEXT["ok"], out)
        self.assertIn("only contains instructions", out)

    def test_a_blocked_skill_says_not_to_install_and_lists_what_it_can_do(self):
        out = report.text(scan_skill(FIX / "sneaky"))
        self.assertIn("DON'T INSTALL", out)
        self.assertIn("It can:", out)
        self.assertIn(report.CAP_TEXT["network"], out)

    def test_findings_are_cut_off_at_the_limit_and_say_how_many_were_left_out(self):
        result = scan_skill(FIX / "sneaky")
        shown = [f for f in result["findings"] if f["severity"] != "info"]
        self.assertGreater(len(shown), 2)
        out = report.text(result, limit=2)
        self.assertIn(f"and {len(shown) - 2} more", out)

    def test_info_findings_are_not_printed(self):
        result = scan_skill(FIX / "clean")
        result["findings"] = [{"severity": "info", "file": "SKILL.md", "line": 1, "message": "just so you know",
                               "snippet": "", "rule": "x"}]
        self.assertNotIn("just so you know", report.text(result))

    def test_hidden_false_alarms_are_counted(self):
        result = scan_skill(FIX / "clean")
        result["suppressed"] = 3
        self.assertIn("3 known false alarm(s) hidden", report.text(result))


class ChangeSinceApproval(unittest.TestCase):
    def diff(self, **over):
        d = {"approved": "2026-10-01", "added": [], "removed": [], "changed": [], "gained": []}
        d.update(over)
        return d

    def test_unchanged_says_so_with_the_approval_date(self):
        out = report.text(scan_skill(FIX / "clean"), diff=self.diff())
        self.assertIn("Unchanged since you approved it on 2026-10-01", out)

    def test_changes_list_each_file_and_any_new_abilities(self):
        d = self.diff(added=["run.sh"], changed=["SKILL.md"], removed=["old.md"], gained=["shell"])
        out = report.text(scan_skill(FIX / "clean"), diff=d)
        self.assertIn("CHANGED since you approved it on 2026-10-01", out)
        for line in ("new file: run.sh", "edited: SKILL.md", "gone: old.md"):
            self.assertIn(line, out)
        self.assertIn("It can now also: " + report.CAP_TEXT["shell"], out)


class MachineReadable(unittest.TestCase):
    def test_json_round_trips(self):
        results = [scan_skill(FIX / "clean"), scan_skill(FIX / "sneaky")]
        self.assertEqual(json.loads(report.as_json(results)), results)

    def test_sarif_has_one_result_per_finding_and_one_rule_per_kind_of_finding(self):
        results = [scan_skill(FIX / "sneaky")]
        sarif = json.loads(report.as_sarif(results))
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        self.assertEqual(run["tool"]["driver"]["name"], "skillgate")
        self.assertEqual(len(run["results"]), len(results[0]["findings"]))
        self.assertEqual(len(run["tool"]["driver"]["rules"]), len({f["rule"] for f in results[0]["findings"]}))

    def test_sarif_lines_start_at_one_and_levels_follow_severity(self):
        sarif = json.loads(report.as_sarif([scan_skill(FIX / "sneaky")]))
        for item in sarif["runs"][0]["results"]:
            self.assertGreaterEqual(item["locations"][0]["physicalLocation"]["region"]["startLine"], 1)
            self.assertIn(item["level"], {"error", "warning", "note"})


if __name__ == "__main__":
    unittest.main()
