"""Remember what you approved, and notice when it changes afterwards."""
import json
import time
from pathlib import Path

DEFAULT = "skillgate.lock.json"


def load(path=DEFAULT):
    p = Path(path)
    return json.loads(p.read_text()) if p.exists() else {"version": 1, "skills": {}}


def approve(result, path=DEFAULT):
    data = load(path)
    data["skills"][result["path"]] = {
        "name": result["skill"],
        "approved": time.strftime("%Y-%m-%d"),
        "capabilities": result["capabilities"],
        "files": result["files"],
    }
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")


def compare(result, path=DEFAULT):
    """Return None if never approved, else a dict describing what moved since approval."""
    entry = load(path)["skills"].get(result["path"])
    if entry is None:
        return None
    old, new = entry["files"], result["files"]
    return {
        "approved": entry["approved"],
        "added": sorted(set(new) - set(old)),
        "removed": sorted(set(old) - set(new)),
        "changed": sorted(f for f in set(old) & set(new) if old[f] != new[f]),
        "gained": sorted(set(result["capabilities"]) - set(entry["capabilities"])),
    }


def is_clean(diff):
    return diff is not None and not (diff["added"] or diff["removed"] or diff["changed"])
