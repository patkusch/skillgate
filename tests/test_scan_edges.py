import tempfile
import unittest
from pathlib import Path

from skillgate import scan


def make(root, files):
    for rel, content in files.items():
        p = Path(root) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    return root


GOOD = "---\nname: demo\ndescription: Formats notes\n---\n# Demo\n"


class Work(unittest.TestCase):
    def setUp(self):
        self._t = tempfile.TemporaryDirectory()
        self.dir = Path(self._t.name)
        self.addCleanup(self._t.cleanup)

    def scan(self, files):
        make(self.dir, {"SKILL.md": GOOD, **files})
        return scan.scan_skill(self.dir)

    def rules(self, result):
        return [f["rule"] for f in result["findings"]]


class Frontmatter(unittest.TestCase):
    def test_keys_are_lower_cased_and_quotes_are_removed(self):
        meta = scan.parse_frontmatter("---\nName: 'demo'\nDescription: \"Formats notes\"\n---\nbody")
        self.assertEqual(meta, {"name": "demo", "description": "Formats notes"})

    def test_a_list_under_a_key_is_joined_into_one_line(self):
        meta = scan.parse_frontmatter("---\nname: x\nallowed-tools:\n  - Read\n  - Grep\n---\n")
        self.assertEqual(meta["allowed-tools"], "Read Grep")

    def test_a_continuation_line_is_added_to_the_key_above(self):
        meta = scan.parse_frontmatter("---\nname: x\ndescription: first\n  second part\n---\n")
        self.assertEqual(meta["description"], "first second part")

    def test_no_front_matter_means_nothing_is_claimed(self):
        self.assertEqual(scan.parse_frontmatter("# Just a heading\n"), {})
        self.assertEqual(scan.parse_frontmatter("---\nname: unclosed\n"), {})
        self.assertEqual(scan.parse_frontmatter(""), {})


class Finding(Work):
    def test_find_skills_takes_a_skill_folder_as_it_is(self):
        make(self.dir, {"SKILL.md": GOOD})
        self.assertEqual(scan.find_skills(self.dir), [self.dir])

    def test_find_skills_walks_a_folder_of_skills_in_order_and_does_not_count_a_skills_own_subfolders(self):
        make(self.dir, {"b/SKILL.md": GOOD, "a/SKILL.md": GOOD, "a/inner/SKILL.md": GOOD, "c/notes.md": "x"})
        self.assertEqual([p.name for p in scan.find_skills(self.dir)], ["a", "b"])

    def test_tool_folders_are_never_searched(self):
        make(self.dir, {"node_modules/pkg/SKILL.md": GOOD, ".git/x/SKILL.md": GOOD, "__pycache__/SKILL.md": GOOD, "real/SKILL.md": GOOD})
        self.assertEqual([p.name for p in scan.find_skills(self.dir)], ["real"])

    def test_nothing_found_gives_an_empty_list(self):
        self.assertEqual(scan.find_skills(self.dir), [])


class Scanning(Work):
    def test_a_skill_with_no_name_or_description_is_told_it_does_not_say_what_it_does(self):
        make(self.dir, {"SKILL.md": "---\nname: only-a-name\n---\n"})
        result = scan.scan_skill(self.dir)
        self.assertIn("no-metadata", self.rules(result))
        self.assertEqual(result["skill"], "only-a-name")

    def test_the_skill_is_named_after_its_folder_when_it_has_no_name(self):
        make(self.dir, {"SKILL.md": "just text"})
        self.assertEqual(scan.scan_skill(self.dir)["skill"], self.dir.name)

    def test_every_file_gets_a_fingerprint_so_a_later_edit_can_be_seen(self):
        result = self.scan({"run.py": "print('hi')\n", "docs/notes.md": "text\n"})
        self.assertEqual(sorted(result["files"]), ["SKILL.md", "docs/notes.md", "run.py"])
        self.assertTrue(all(len(h) == 64 for h in result["files"].values()))
        again = self.scan({"run.py": "print('hi')\n", "docs/notes.md": "text\n"})
        self.assertEqual(result["files"], again["files"])
        edited = self.scan({"run.py": "print('bye')\n"})
        self.assertNotEqual(result["files"]["run.py"], edited["files"]["run.py"])

    def test_a_file_that_is_not_readable_text_is_flagged_because_it_cannot_be_checked(self):
        result = self.scan({"tool.bin": b"\x00\x01\x02binary", "image.png": b"\x89PNG\r\n"})
        opaque = [f for f in result["findings"] if f["rule"] == "opaque-file"]
        self.assertEqual(sorted(f["file"] for f in opaque), ["image.png", "tool.bin"])
        self.assertTrue(all(f["severity"] == "medium" for f in opaque))
        self.assertEqual(result["verdict"], "review")

    def test_a_text_file_with_a_hidden_null_byte_is_treated_as_opaque_too(self):
        result = self.scan({"notes.md": b"fine\x00then hidden"})
        self.assertIn("opaque-file", self.rules(result))

    def test_invisible_characters_are_a_high_severity_finding_with_the_line_number(self):
        result = self.scan({"notes.md": "line one\nsneaky​text\n"})
        hidden = [f for f in result["findings"] if f["rule"] == "hidden-chars"]
        self.assertEqual((len(hidden), hidden[0]["line"], hidden[0]["file"]), (1, 2, "notes.md"))
        self.assertEqual(hidden[0]["severity"], "high")
        self.assertEqual(result["verdict"], "block")

    def test_a_file_over_the_size_limit_is_flagged_and_only_its_start_is_read(self):
        big = ("x" * 99 + "\n") * (scan.MAX_BYTES // 100 + 50)
        result = self.scan({"big.txt": big})
        self.assertIn("too-big", self.rules(result))
        self.assertEqual(len(result["files"]["big.txt"]), 64, "the whole file is still fingerprinted")

    def test_findings_come_worst_first_then_by_file_and_line(self):
        result = self.scan({"a.md": "x​\n", "b.bin": b"\x00"})
        order = ["high", "medium", "low"]
        ranks = [order.index(f["severity"]) for f in result["findings"]]
        self.assertEqual(ranks, sorted(ranks))

    def test_a_long_snippet_is_cut_to_160_characters(self):
        result = self.scan({"a.md": "y" * 400 + "​\n"})
        hidden = next(f for f in result["findings"] if f["rule"] == "hidden-chars")
        self.assertLessEqual(len(hidden["snippet"]), 160)

    def test_the_verdict_is_ok_review_or_block_by_the_worst_severity(self):
        f = lambda sev: {"severity": sev}
        self.assertEqual(scan.verdict([]), "ok")
        self.assertEqual(scan.verdict([f("low")]), "ok")
        self.assertEqual(scan.verdict([f("low"), f("medium")]), "review")
        self.assertEqual(scan.verdict([f("medium"), f("high")]), "block")

    def test_the_kind_of_file_decides_which_rules_apply(self):
        self.assertEqual(scan.kind_of(Path("run.py"), b"im"), "code")
        self.assertEqual(scan.kind_of(Path("tool"), b"#!"), "code", "a script with a shebang is code whatever it is called")
        self.assertEqual(scan.kind_of(Path("notes.md"), b"# "), "text")
        self.assertEqual(scan.kind_of(Path("README"), b"Hi"), "text", "no extension is read as text")
        self.assertEqual(scan.kind_of(Path("pic.png"), b"\x89P"), "other")


class Declared(Work):
    def test_a_skill_that_asks_for_bash_without_limits_is_flagged_for_review(self):
        make(self.dir, {"SKILL.md": "---\nname: d\ndescription: Formats notes\nallowed-tools: Bash, Read\n---\n"})
        self.assertIn("bash-unrestricted", self.rules(scan.scan_skill(self.dir)))

    def test_a_limited_bash_is_not_unrestricted(self):
        make(self.dir, {"SKILL.md": "---\nname: d\ndescription: Formats notes\nallowed-tools: Bash(git status), Read\n---\n"})
        self.assertNotIn("bash-unrestricted", self.rules(scan.scan_skill(self.dir)))


if __name__ == "__main__":
    unittest.main()
