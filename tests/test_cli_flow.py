import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from skillgate import cli

FIX = Path(__file__).parent.parent / "fixtures"


def call(argv):
    out, err = io.StringIO(), io.StringIO()
    code = None
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = cli.main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class Work(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)
        self.addCleanup(self._t.cleanup)
        self.lock = str(self.dir / "skills.lock")
        self.clean = self.dir / "clean"
        shutil.copytree(FIX / "clean", self.clean)
        self.sneaky = self.dir / "sneaky"
        shutil.copytree(FIX / "sneaky", self.sneaky)
        self.none = str(self.dir / "no-ignore-file")  # a path that does not exist, so no ignores apply


class IgnoreFile(Work):
    def test_each_line_is_skill_rule_file_with_wildcards_and_a_comment_allowed(self):
        f = self.dir / "ignore"
        f.write_text("# a heading\n\nsneaky net.* *.py   # known false alarm\nbad line only two\n* * *\n")
        self.assertEqual(cli.load_ignores(str(f)), [("sneaky", "net.*", "*.py"), ("*", "*", "*")])

    def test_a_missing_ignore_file_means_no_ignores(self):
        self.assertEqual(cli.load_ignores(self.none), [])

    def test_a_matching_line_hides_a_finding_and_the_verdict_is_worked_out_again(self):
        result = {"skill": "demo", "findings": [{"rule": "net.fetch", "file": "run.py", "severity": "high"},
                                                {"rule": "shell.exec", "file": "run.py", "severity": "high"}], "verdict": "block"}
        out = cli.apply_ignores(result, [("demo", "net.*", "*.py")])
        self.assertEqual(out["suppressed"], 1)
        self.assertEqual([f["rule"] for f in out["findings"]], ["shell.exec"])
        again = cli.apply_ignores({"skill": "demo", "findings": list(out["findings"]), "verdict": "block"}, [("demo", "shell.*", "*")])
        self.assertEqual((again["suppressed"], again["findings"]), (1, []))
        self.assertEqual(again["verdict"], "ok")

    def test_a_line_for_a_different_skill_changes_nothing(self):
        result = {"skill": "demo", "findings": [{"rule": "net.fetch", "file": "run.py", "severity": "high"}], "verdict": "block"}
        self.assertEqual(cli.apply_ignores(result, [("other", "*", "*")])["suppressed"], 0)


class Flow(Work):
    def test_fail_on_decides_the_exit_code(self):
        self.assertEqual(call(["scan", str(self.sneaky), "--ignore", self.none])[0], 1, "block is the default threshold")
        self.assertEqual(call(["scan", str(self.sneaky), "--ignore", self.none, "--fail-on", "never"])[0], 0)
        self.assertEqual(call(["scan", str(self.clean), "--ignore", self.none, "--fail-on", "review"])[0], 0)

    def test_json_and_sarif_outputs_are_valid_documents(self):
        code, out, _ = call(["scan", str(self.sneaky), "--ignore", self.none, "--json", "--fail-on", "never"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out))
        _, out, _ = call(["scan", str(self.sneaky), "--ignore", self.none, "--sarif", "--fail-on", "never"])
        self.assertEqual(json.loads(out)["version"], "2.1.0")

    def test_a_folder_with_no_skill_in_it_is_a_clear_exit_2(self):
        empty = self.dir / "empty"
        empty.mkdir()
        code, out, err = call(["scan", str(empty), "--ignore", self.none])
        self.assertEqual(code, 2)
        self.assertIn("No SKILL.md found under", err)
        self.assertEqual(out, "")

    def test_a_blocked_skill_is_not_approved_without_force_and_nothing_is_written(self):
        code, out, _ = call(["approve", str(self.sneaky), "--lock", self.lock])
        self.assertEqual(code, 1)
        self.assertIn("Not approved. Fix it, or use --force", out)
        self.assertFalse(Path(self.lock).exists())

    def test_approve_then_verify_is_clean_and_an_edit_afterwards_is_caught(self):
        code, out, _ = call(["approve", str(self.clean), "--lock", self.lock])
        self.assertEqual(code, 0)
        self.assertRegex(out, r"Approved .* \(\d+ files\) -> ")
        self.assertEqual(call(["verify", str(self.clean), "--lock", self.lock])[0], 0)
        (self.clean / "SKILL.md").write_text((self.clean / "SKILL.md").read_text() + "\nNew instruction.\n")
        code, out, _ = call(["verify", str(self.clean), "--lock", self.lock])
        self.assertEqual(code, 1)
        self.assertTrue(out.strip())

    def test_verify_of_a_skill_that_was_never_approved_says_how_to_approve_it(self):
        code, out, _ = call(["verify", str(self.clean), "--lock", self.lock])
        self.assertEqual(code, 1)
        self.assertRegex(out, r"never approved\. Run: skillgate approve ")

    def test_the_worst_verdict_across_many_skills_decides(self):
        self.assertEqual(cli._worst([]), 0)
        self.assertEqual(cli._worst([{"verdict": "ok"}, {"verdict": "review"}]), 1)
        self.assertEqual(cli._worst([{"verdict": "ok"}, {"verdict": "block"}, {"verdict": "review"}]), 2)


class Download(Work):
    def run_fetch(self, url, returncode=0, stderr=""):
        done = mock.Mock(returncode=returncode, stderr=stderr)
        with mock.patch("skillgate.cli.subprocess.run", return_value=done) as run, \
             mock.patch("skillgate.cli.tempfile.mkdtemp", return_value=str(self.dir / "clone")):
            try:
                result = cli.fetch_github(url)
            except SystemExit as e:
                result = ("exit", e.code)
        return result, run

    def test_only_github_links_are_accepted_and_others_are_refused_before_anything_runs(self):
        err = io.StringIO()
        for bad in ("https://gitlab.com/a/b", "http://github.com/a/b", "https://github.com/onlyowner", "file:///etc/passwd"):
            with contextlib.redirect_stderr(err):
                result, run = self.run_fetch(bad)
            self.assertEqual(result, ("exit", 2), bad)
            run.assert_not_called()
        self.assertIn("Only https://github.com/owner/repo", err.getvalue())

    def test_a_repo_link_is_a_shallow_clone_with_git_hooks_switched_off(self):
        result, run = self.run_fetch("https://github.com/acme/skills.git")
        cmd = run.call_args.args[0]
        self.assertEqual(result, str(self.dir / "clone"))
        self.assertEqual(cmd[:3], ["git", "clone", "--depth"])
        self.assertIn("core.hooksPath=/dev/null", cmd)
        self.assertNotIn("--branch", cmd)
        self.assertEqual(cmd[-2], "https://github.com/acme/skills.git")

    def test_a_tree_link_picks_the_branch_and_returns_the_folder_inside(self):
        result, run = self.run_fetch("https://github.com/acme/skills/tree/dev/tools/one")
        cmd = run.call_args.args[0]
        self.assertEqual(cmd[cmd.index("--branch") + 1], "dev")
        self.assertEqual(result, str(self.dir / "clone" / "tools" / "one"))

    def test_a_failed_download_says_why_and_exits_2(self):
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            result, _ = self.run_fetch("https://github.com/acme/missing", returncode=128, stderr="repository not found\n")
        self.assertEqual(result, ("exit", 2))
        self.assertIn("Could not download https://github.com/acme/missing: repository not found", err.getvalue())


if __name__ == "__main__":
    unittest.main()
