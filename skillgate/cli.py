import argparse
import fnmatch
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from . import lock, report
from .rules import SEVERITIES
from .scan import find_skills, scan_skill, verdict


IGNORE_FILE = "skillgate.ignore"


def load_ignores(path):
    """Lines of `skill rule file  # reason`. Read from outside the skill, so a skill can't excuse itself."""
    p = Path(path)
    if not p.exists():
        return []
    rows = []
    for line in p.read_text().splitlines():
        line = line.split("#", 1)[0].split()
        if len(line) == 3:
            rows.append(tuple(line))
    return rows


def apply_ignores(result, rows):
    def hit(f):
        return any(fnmatch.fnmatch(result["skill"], s) and fnmatch.fnmatch(f["rule"], r) and fnmatch.fnmatch(f["file"], fl)
                   for s, r, fl in rows)
    kept = [f for f in result["findings"] if not hit(f)]
    result["suppressed"] = len(result["findings"]) - len(kept)
    result["findings"] = kept
    result["verdict"] = verdict(kept)
    return result


def fetch_github(url):
    """Shallow-clone a GitHub repo (or a folder inside it) to a temp folder. Nothing in it is run."""
    m = re.match(r"^https://github\.com/([\w.-]+)/([\w.-]+?)(?:\.git)?(?:/tree/([^/]+)(?:/(.*))?)?/?$", url)
    if not m:
        print("Only https://github.com/owner/repo[/tree/branch/path] links are supported.", file=sys.stderr)
        sys.exit(2)
    owner, repo, branch, sub = m.groups()
    tmp = tempfile.mkdtemp(prefix="skillgate-")
    cmd = ["git", "clone", "--depth", "1", "-q", "-c", "core.hooksPath=/dev/null"]
    if branch:
        cmd += ["--branch", branch]
    r = subprocess.run(cmd + [f"https://github.com/{owner}/{repo}.git", tmp], capture_output=True, text=True)
    if r.returncode:
        print(f"Could not download {url}: {r.stderr.strip()}", file=sys.stderr)
        sys.exit(2)
    return str(Path(tmp) / sub) if sub else tmp


def _scan_all(path, ignore=IGNORE_FILE):
    if path.startswith("https://"):
        path = fetch_github(path)
    skills = find_skills(path)
    if not skills:
        print(f"No SKILL.md found under {path}", file=sys.stderr)
        sys.exit(2)
    rows = load_ignores(ignore)
    return [apply_ignores(scan_skill(s), rows) for s in skills]


def _worst(results):
    order = {"ok": 0, "review": 1, "block": 2}
    return max((order[r["verdict"]] for r in results), default=0)


def main(argv=None):
    p = argparse.ArgumentParser(prog="skillgate", description="Check an agent skill before you install it.")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="check a skill (or a folder of skills)")
    s.add_argument("path")
    s.add_argument("--json", action="store_true")
    s.add_argument("--sarif", action="store_true", help="output for GitHub code scanning")
    s.add_argument("--fail-on", choices=["review", "block", "never"], default="block")
    s.add_argument("--lock", default=lock.DEFAULT)
    s.add_argument("--ignore", default=IGNORE_FILE, help="known false alarms: `skill rule file  # reason` per line")

    a = sub.add_parser("approve", help="record that you have read this skill and accept it as it is")
    a.add_argument("path")
    a.add_argument("--force", action="store_true", help="approve even if the verdict is DON'T INSTALL")
    a.add_argument("--lock", default=lock.DEFAULT)

    v = sub.add_parser("verify", help="check approved skills haven't changed")
    v.add_argument("path")
    v.add_argument("--lock", default=lock.DEFAULT)

    args = p.parse_args(argv)
    results = _scan_all(args.path, getattr(args, 'ignore', IGNORE_FILE))

    if args.cmd == "scan":
        if args.json:
            print(report.as_json(results))
        elif args.sarif:
            print(report.as_sarif(results))
        else:
            print("\n\n".join(report.text(r, lock.compare(r, args.lock)) for r in results))
        level = {"review": 1, "block": 2, "never": 99}[args.fail_on]
        return 1 if _worst(results) >= level else 0

    if args.cmd == "approve":
        bad = [r for r in results if r["verdict"] == "block" and not args.force]
        for r in bad:
            print(report.text(r))
            print("\nNot approved. Fix it, or use --force if you have read it and accept the risk.")
        if bad:
            return 1
        for r in results:
            lock.approve(r, args.lock)
            print(f"Approved {r['skill']} ({len(r['files'])} files) -> {args.lock}")
        return 0

    if args.cmd == "verify":
        code = 0
        for r in results:
            d = lock.compare(r, args.lock)
            if d is None:
                print(f"{r['skill']}: never approved. Run: skillgate approve {r['path']}")
                code = 1
            else:
                print(report.text(r, d))
                if not lock.is_clean(d):
                    code = 1
        return code


if __name__ == "__main__":
    sys.exit(main())
