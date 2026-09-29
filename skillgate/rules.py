"""The rules. Each one says what to look for, how bad it is, and what it means in plain English."""
import re
from dataclasses import dataclass

SEVERITIES = ["info", "low", "medium", "high"]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    capability: str  # what the skill would be able to do
    pattern: "re.Pattern"
    applies: str  # "code", "text" or "any"
    message: str


def _r(id, sev, cap, pat, applies, msg):
    return Rule(id, sev, cap, re.compile(pat, re.I), applies, msg)


RULES = [
    # --- what the code can reach
    _r("net-request", "medium", "network",
       r"\b(requests\.(get|post|put)|urllib\.request|urlopen|http\.client|httpx|aiohttp|fetch\(|axios|XMLHttpRequest|socket\.connect|\bcurl\b|\bwget\b|Invoke-WebRequest)",
       "code", "Talks to the internet."),
    _r("shell-exec", "medium", "shell",
       r"\b(subprocess\.|os\.system|os\.popen|child_process|execSync|spawnSync|Runtime\.getRuntime\(\)\.exec)",
       "code", "Runs other programs on your machine."),
    _r("dyn-exec", "high", "shell",
       r"(\beval\(|\bexec\(|new Function\(|__import__\(|compile\()",
       "code", "Runs code it builds on the fly, so you can't read what it will do."),
    _r("secret-env", "medium", "secrets",
       r"(os\.environ|process\.env|getenv\()",
       "code", "Reads environment variables, which is where keys and tokens usually live."),
    _r("secret-files", "high", "secrets",
       r"(\.ssh/|id_rsa|id_ed25519|\.aws/|\.npmrc|\.netrc|\.git-credentials|keychain|credentials\.json|\.kube/config|\.docker/config)",
       "any", "Goes near key, password or credential files."),
    _r("secret-dotenv", "medium", "secrets", r"\.env\b", "any", "Mentions a .env file, where projects keep their secrets."),
    _r("persist", "high", "persistence",
       r"(crontab|launchctl|LaunchAgents|systemd|\.bashrc|\.zshrc|\.zprofile|\.bash_profile|\.git/hooks|authorized_keys|schtasks)",
       "any", "Sets itself up to keep running or to run again later."),
    _r("write-outside", "medium", "outside-write",
       r"(~/|\$HOME|os\.path\.expanduser|Path\.home\(\)|/etc/|/usr/local|/Library/|C:\\\\Users)",
       "code", "Reaches into your home folder or system folders, outside its own folder."),
    _r("install", "medium", "install",
       r"(pip3? install|npm (i|install)\b|npx\s|brew install|apt(-get)? install|gem install|go install|cargo install)",
       "any", "Installs other software when it runs."),
    _r("pipe-shell", "high", "install",
       r"(curl|wget)[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b",
       "any", "Downloads something and runs it without showing it to you first."),
    _r("obfuscated", "high", "obfuscation",
       r"(base64\.b64decode|atob\(|b64decode|fromCharCode|codecs\.decode\([^)]*rot|\\x[0-9a-f]{2}(\\x[0-9a-f]{2}){12,}|[A-Za-z0-9+/]{200,}={0,2})",
       "code", "Contains hidden or scrambled text, a common way to hide what code really does."),
    _r("destructive", "high", "destructive",
       r"(rm\s+-rf?\s+(/|~|\$HOME)|shutil\.rmtree\(\s*(['\"]/|Path\.home)|git push\s+(-f|--force)|drop\s+(table|database)|mkfs\b|dd\s+if=)",
       "any", "Can delete or overwrite things that are hard to get back."),
    # --- what the words try to make the AI do
    _r("inject-override", "high", "injection",
       r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|system|safety)\s+(instructions|rules|prompts?|guidelines)",
       "text", "Tells the AI to drop its own rules."),
    _r("inject-secrecy", "high", "injection",
       r"(do not|don't|never)\s+(tell|inform|mention|show|reveal|let)\s+(the\s+)?(user|human|person)",
       "text", "Tells the AI to hide something from you."),
    _r("inject-exfil", "high", "injection",
       r"(send|post|upload|forward|email|exfiltrate)\s+[^.\n]{0,60}(to|at)\s+(https?://|[\w.-]+@[\w.-]+)",
       "text", "Tells the AI to send your data to an outside address."),
    _r("inject-skipconsent", "medium", "injection",
       r"(without\s+(asking|confirmation|permission|approval)|skip\s+(the\s+)?(confirmation|approval|permission)|--dangerously|bypass\s+(permissions?|approval|sandbox)|auto-?approve)",
       "any", "Tells the AI to act without checking with you first."),
    _r("inject-hidden-comment", "medium", "injection",
       r"<!--[^>]{20,}(ignore|instruction|always|must|secret|send|run)[^>]*-->",
       "text", "Has instructions tucked into an HTML comment you won't see when reading it rendered."),
]

# Characters people can't see but the AI can read.
INVISIBLE = re.compile("[\u200b\u200c\u200d\u2060\ufeff\u202a-\u202e\u2066-\u2069\U000e0000-\U000e007f]")

CODE_EXT = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".ps1", ".go", ".rs", ".php", ".lua"}
TEXT_EXT = {".md", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml"}

# Prose that merely mentions these things is less alarming than code that does them.
DOCS_DOWNGRADE = {"secrets", "persistence", "destructive", "install"}
