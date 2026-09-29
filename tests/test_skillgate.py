import json
import shutil
import tempfile
import unittest
from pathlib import Path

from skillgate import lock
from skillgate.cli import main
from skillgate.scan import find_skills, scan_skill

FIX = Path(__file__).parent.parent / "fixtures"


class Scan(unittest.TestCase):
    def test_clean_skill_is_ok(self):
        r = scan_skill(FIX / "clean")
        self.assertEqual(r["verdict"], "ok")
        self.assertEqual(r["capabilities"], [])

    def test_sneaky_skill_is_blocked_with_every_capability(self):
        r = scan_skill(FIX / "sneaky")
        self.assertEqual(r["verdict"], "block")
        for cap in ("network", "shell", "secrets", "persistence", "injection"):
            self.assertIn(cap, r["capabilities"])

    def test_hidden_characters_found(self):
        rules = {f["rule"] for f in scan_skill(FIX / "sneaky")["findings"]}
        self.assertIn("hidden-chars", rules)

    def test_declared_vs_actual(self):
        rules = {f["rule"] for f in scan_skill(FIX / "sneaky")["findings"]}
        self.assertIn("says-nothing-about-internet", rules)
        self.assertIn("shell-not-declared", rules)

    def test_finds_skills_in_a_folder(self):
        self.assertEqual(len(find_skills(FIX)), 2)

    def test_binary_file_is_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "clean", Path(d) / "s")
            (Path(d) / "s" / "tool.bin").write_bytes(b"\x00\x01\x02")
            rules = {f["rule"] for f in scan_skill(Path(d) / "s")["findings"]}
            self.assertIn("opaque-file", rules)


class Lock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.skill = Path(self.tmp) / "s"
        shutil.copytree(FIX / "clean", self.skill)
        self.lockfile = str(Path(self.tmp) / "lock.json")

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_unchanged_then_rug_pull(self):
        self.assertEqual(main(["approve", str(self.skill), "--lock", self.lockfile]), 0)
        self.assertEqual(main(["verify", str(self.skill), "--lock", self.lockfile]), 0)
        (self.skill / "run.py").write_text("import requests\nrequests.get('https://x.example')\n")
        d = lock.compare(scan_skill(self.skill), self.lockfile)
        self.assertEqual(d["added"], ["run.py"])
        self.assertIn("network", d["gained"])
        self.assertEqual(main(["verify", str(self.skill), "--lock", self.lockfile]), 1)

    def test_blocked_skill_is_not_approved_without_force(self):
        self.assertEqual(main(["approve", str(FIX / "sneaky"), "--lock", self.lockfile]), 1)
        self.assertFalse(Path(self.lockfile).exists())
        self.assertEqual(main(["approve", str(FIX / "sneaky"), "--force", "--lock", self.lockfile]), 0)

    def test_never_approved_fails_verify(self):
        self.assertEqual(main(["verify", str(self.skill), "--lock", self.lockfile]), 1)


class Output(unittest.TestCase):
    def test_exit_codes(self):
        self.assertEqual(main(["scan", str(FIX / "clean")]), 0)
        self.assertEqual(main(["scan", str(FIX / "sneaky")]), 1)
        self.assertEqual(main(["scan", str(FIX / "sneaky"), "--fail-on", "never"]), 0)

    def test_sarif_is_valid_json_with_results(self):
        import contextlib
        import io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            main(["scan", str(FIX / "sneaky"), "--sarif"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data["version"], "2.1.0")
        self.assertTrue(data["runs"][0]["results"])


if __name__ == "__main__":
    unittest.main()


class Ignore(unittest.TestCase):
    def test_ignore_file_clears_a_known_false_alarm(self):
        with tempfile.TemporaryDirectory() as d:
            ig = Path(d) / "skillgate.ignore"
            ig.write_text("format-helper * *  # test\n")
            self.assertEqual(main(["scan", str(FIX / "sneaky"), "--ignore", str(ig)]), 0)

    def test_skill_cannot_ignore_itself(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "sneaky", Path(d) / "s")
            (Path(d) / "s" / "skillgate.ignore").write_text("* * *\n")
            self.assertEqual(main(["scan", str(Path(d) / "s"), "--ignore", str(Path(d) / "none")]), 1)

    def test_bad_url_is_refused(self):
        with self.assertRaises(SystemExit):
            main(["scan", "https://evil.example/x"])


class FalseAlarms(unittest.TestCase):
    def test_regex_compile_and_exec_are_not_dynamic_code(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "clean", Path(d) / "s")
            (Path(d) / "s" / "a.py").write_text("import re\nX = re.compile('a')\nm = X.exec('b')\n")
            self.assertEqual(scan_skill(Path(d) / "s")["verdict"], "ok")

    def test_real_eval_is_still_caught(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "clean", Path(d) / "s")
            (Path(d) / "s" / "a.py").write_text("eval(input())\n")
            self.assertEqual(scan_skill(Path(d) / "s")["verdict"], "block")


class Comments(unittest.TestCase):
    def test_comment_mentioning_ssh_is_not_high(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "clean", Path(d) / "s")
            (Path(d) / "s" / "a.py").write_text("# never read ~/.ssh/id_rsa here\n")
            self.assertEqual(scan_skill(Path(d) / "s")["verdict"], "review")

    def test_advice_to_agents_is_not_secrecy(self):
        with tempfile.TemporaryDirectory() as d:
            shutil.copytree(FIX / "clean", Path(d) / "s")
            (Path(d) / "s" / "a.md").write_text("Do not tell the user they need to switch formats.\n")
            self.assertEqual(scan_skill(Path(d) / "s")["verdict"], "ok")
