import contextlib
import io
import re
import unittest
from pathlib import Path

import skillgate
from skillgate.cli import main


class Version(unittest.TestCase):
    def test_version_flag_prints_the_name_and_number_and_stops(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit) as cm:
            main(["--version"])
        self.assertEqual(cm.exception.code, 0)
        self.assertEqual(out.getvalue().strip(), f"skillgate {skillgate.__version__}")

    def test_the_number_matches_pyproject(self):
        text = (Path(__file__).resolve().parents[1] / "pyproject.toml").read_text()
        declared = re.search(r'^version = "([^"]+)"', text, re.M).group(1)
        self.assertEqual(skillgate.__version__, declared)


if __name__ == "__main__":
    unittest.main()
