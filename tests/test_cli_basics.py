import contextlib
import io
import unittest

from skillgate.cli import main


def run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(argv)
        except SystemExit as e:
            code = e.code
    return code, out.getvalue(), err.getvalue()


class CommandLine(unittest.TestCase):
    def test_help_exits_cleanly_and_names_the_tool(self):
        code, out, _ = run(["--help"])
        self.assertEqual(code, 0)
        self.assertIn("skillgate", out)

    def test_an_option_before_a_command_is_refused_and_nothing_runs(self):
        code, out, err = run(["--nope"])
        self.assertEqual(code, 2)
        self.assertEqual(out, "")
        self.assertIn("error", err)

    def test_no_command_is_refused_with_a_usage_message(self):
        code, out, err = run([])
        self.assertEqual(code, 2)
        self.assertIn("usage", err.lower())

    def test_an_unknown_command_is_refused(self):
        code, _, err = run(["bogus"])
        self.assertEqual(code, 2)
        self.assertIn("bogus", err)


if __name__ == "__main__":
    unittest.main()
