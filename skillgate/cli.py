import argparse
import sys

from . import lock, report
from .rules import SEVERITIES
from .scan import find_skills, scan_skill


def _scan_all(path):
    skills = find_skills(path)
    if not skills:
        print(f"No SKILL.md found under {path}", file=sys.stderr)
        sys.exit(2)
    return [scan_skill(s) for s in skills]


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

    a = sub.add_parser("approve", help="record that you have read this skill and accept it as it is")
    a.add_argument("path")
    a.add_argument("--force", action="store_true", help="approve even if the verdict is DON'T INSTALL")
    a.add_argument("--lock", default=lock.DEFAULT)

    v = sub.add_parser("verify", help="check approved skills haven't changed")
    v.add_argument("path")
    v.add_argument("--lock", default=lock.DEFAULT)

    args = p.parse_args(argv)
    results = _scan_all(args.path)

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
