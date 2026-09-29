"""Read a skill folder and work out what it can touch, what it says, and how those compare."""
import hashlib
import os
import re
from pathlib import Path

from .rules import CODE_EXT, DOCS_DOWNGRADE, INVISIBLE, RULES, SEVERITIES, TEXT_EXT

MAX_BYTES = 2_000_000
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv"}
NET_WORDS = re.compile(r"\b(web|http|https|api|fetch|download|online|internet|url|search|browse|network|remote|cloud|upload|scrape)\b", re.I)


def find_skills(root):
    root = Path(root)
    if (root / "SKILL.md").is_file():
        return [root]
    found = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        if "SKILL.md" in files:
            found.append(Path(dirpath))
            dirs[:] = []  # a skill's own subfolders aren't separate skills
    return sorted(found)


def parse_frontmatter(text):
    m = re.match(r"^---\s*\n(.*?)\n---\s*(\n|$)", text, re.S)
    if not m:
        return {}
    out, key = {}, None
    for line in m.group(1).splitlines():
        kv = re.match(r"^([A-Za-z_-]+)\s*:\s*(.*)$", line)
        if kv:
            key = kv.group(1).lower()
            out[key] = kv.group(2).strip().strip("'\"")
        elif key and line.strip():
            out[key] = (out[key] + " " + line.strip().lstrip("- ")).strip()
    return out


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def list_files(skill):
    files = []
    for dirpath, dirs, names in os.walk(skill):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS)
        for n in sorted(names):
            files.append(Path(dirpath) / n)
    return files


def kind_of(path, head):
    ext = path.suffix.lower()
    if ext in CODE_EXT or head.startswith(b"#!"):
        return "code"
    if ext in TEXT_EXT or ext == "":
        return "text"
    return "other"


def _finding(rule_id, sev, cap, file, line, snippet, msg):
    return {"rule": rule_id, "severity": sev, "capability": cap, "file": file,
            "line": line, "snippet": snippet.strip()[:160], "message": msg}


def scan_skill(skill):
    skill = Path(skill)
    findings, files_hash = [], {}
    text = (skill / "SKILL.md").read_text(errors="replace")
    meta = parse_frontmatter(text)

    if not meta.get("name") or not meta.get("description"):
        findings.append(_finding("no-metadata", "low", "metadata", "SKILL.md", 1, "",
                                 "SKILL.md is missing its name or description, so you can't tell what it claims to do."))

    for path in list_files(skill):
        rel = str(path.relative_to(skill))
        try:
            size = path.stat().st_size
            files_hash[rel] = sha256(path)
            with open(path, "rb") as f:
                raw = f.read(MAX_BYTES)
        except OSError:
            continue
        kind = kind_of(path, raw[:2])
        if b"\x00" in raw[:4096] or kind == "other":
            findings.append(_finding("opaque-file", "medium", "obfuscation", rel, 0, "",
                                     f"Contains a file that isn't readable text ({size} bytes), so it can't be checked."))
            continue
        if size > MAX_BYTES:
            findings.append(_finding("too-big", "low", "obfuscation", rel, 0, "",
                                     "File is too large to read in full; only the start was checked."))
        body = raw.decode("utf-8", errors="replace")
        for ln, line in enumerate(body.splitlines(), 1):
            if INVISIBLE.search(line):
                findings.append(_finding("hidden-chars", "high", "injection", rel, ln, repr(line[:80]),
                                         "Contains invisible characters. The AI can read them; you can't."))
            for rule in RULES:
                if rule.applies == "code" and kind != "code":
                    continue
                if rule.applies == "text" and kind != "text":
                    continue
                if rule.pattern.search(line):
                    sev = rule.severity
                    is_comment = kind == "code" and line.lstrip().startswith(("#", "//", "*", "/*", "--"))
                    if (kind == "text" or is_comment) and rule.capability in DOCS_DOWNGRADE:
                        sev = SEVERITIES[max(SEVERITIES.index(sev) - 1, 0)]
                    findings.append(_finding(rule.id, sev, rule.capability, rel, ln, line, rule.message))

    caps = sorted({f["capability"] for f in findings if f["capability"] not in ("metadata",)})
    findings += declared_vs_actual(meta, findings)
    findings.sort(key=lambda f: (-SEVERITIES.index(f["severity"]), f["file"], f["line"]))
    return {
        "skill": meta.get("name") or skill.name,
        "path": str(skill),
        "description": meta.get("description", ""),
        "verdict": verdict(findings),
        "capabilities": caps,
        "findings": findings,
        "files": files_hash,
    }


def declared_vs_actual(meta, findings):
    """Compare what the skill says about itself with what its files do."""
    out = []
    caps = {f["capability"] for f in findings}
    tools = re.split(r"[,\s]+", meta.get("allowed-tools", "")) if meta.get("allowed-tools") else []
    tools_l = [t.lower() for t in tools if t]
    if "network" in caps and not NET_WORDS.search(meta.get("description", "")):
        out.append(_finding("says-nothing-about-internet", "medium", "network", "SKILL.md", 1, meta.get("description", "")[:80],
                            "The code uses the internet, but the description never mentions it."))
    if tools_l:
        if "shell" in caps and not any(t.startswith("bash") for t in tools_l):
            out.append(_finding("shell-not-declared", "medium", "shell", "SKILL.md", 1, meta.get("allowed-tools", ""),
                                "The code runs programs, but the skill doesn't list Bash among the tools it needs."))
        if "bash" in tools_l:
            out.append(_finding("bash-unrestricted", "medium", "shell", "SKILL.md", 1, meta.get("allowed-tools", ""),
                                "Asks for Bash with no limits, so it can run any command."))
    return out


def verdict(findings):
    sevs = {f["severity"] for f in findings}
    if "high" in sevs:
        return "block"
    if "medium" in sevs:
        return "review"
    return "ok"
