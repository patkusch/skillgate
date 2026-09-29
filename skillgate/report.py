import json

from . import __version__

CAP_TEXT = {
    "network": "reach the internet",
    "shell": "run programs on your machine",
    "secrets": "read keys, tokens or credential files",
    "persistence": "keep itself running or come back later",
    "outside-write": "touch files outside its own folder",
    "install": "install other software",
    "obfuscation": "hide what it does",
    "destructive": "delete or overwrite things",
    "injection": "steer the AI in ways you can't see",
}
VERDICT_TEXT = {
    "ok": "OK. Nothing risky found.",
    "review": "REVIEW. Read the flagged lines before you install.",
    "block": "DON'T INSTALL yet. Something serious needs a human look.",
}


def text(result, diff=None, limit=8):
    out = [f"{result['skill']}  ({result['path']})", f"  {VERDICT_TEXT[result['verdict']]}"]
    if result["capabilities"]:
        can = [CAP_TEXT[c] for c in result["capabilities"] if c in CAP_TEXT]
        if can:
            out.append("  It can: " + "; ".join(can) + ".")
    else:
        out.append("  It only contains instructions and stays inside its own folder.")
    if diff is not None:
        out += _diff_text(diff)
    seen = 0
    for f in result["findings"]:
        if f["severity"] == "info":
            continue
        if seen == limit:
            out.append(f"  ... and {len([x for x in result['findings'] if x['severity'] != 'info']) - limit} more (use --json for all).")
            break
        where = f"{f['file']}:{f['line']}" if f["line"] else f["file"]
        out.append(f"  [{f['severity']}] {where}: {f['message']}")
        if f["snippet"]:
            out.append(f"         {f['snippet']}")
        seen += 1
    return "\n".join(out)


def _diff_text(d):
    if not (d["added"] or d["removed"] or d["changed"]):
        return [f"  Unchanged since you approved it on {d['approved']}."]
    out = [f"  CHANGED since you approved it on {d['approved']}:"]
    for label, key in (("new file", "added"), ("edited", "changed"), ("gone", "removed")):
        for f in d[key]:
            out.append(f"    {label}: {f}")
    if d["gained"]:
        out.append("  It can now also: " + "; ".join(CAP_TEXT.get(c, c) for c in d["gained"]) + ".")
    return out


def as_json(results):
    return json.dumps(results, indent=2)


def as_sarif(results):
    level = {"high": "error", "medium": "warning", "low": "note", "info": "note"}
    rules, seen, items = [], set(), []
    for r in results:
        for f in r["findings"]:
            if f["rule"] not in seen:
                seen.add(f["rule"])
                rules.append({"id": f["rule"], "shortDescription": {"text": f["message"]}})
            path = f"{r['path'].rstrip('/')}/{f['file']}"
            items.append({
                "ruleId": f["rule"], "level": level[f["severity"]],
                "message": {"text": f["message"]},
                "locations": [{"physicalLocation": {"artifactLocation": {"uri": path},
                                                    "region": {"startLine": max(f["line"], 1)}}}],
            })
    return json.dumps({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                       "runs": [{"tool": {"driver": {"name": "skillgate", "version": __version__, "rules": rules}},
                                 "results": items}]}, indent=2)
