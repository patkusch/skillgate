# skillgate

Check an agent skill before you install it.

Skills are folders of instructions and scripts that your AI agent follows. Most people install them without reading them. skillgate reads them for you and tells you, in plain English:

1. **What it can do.** Reach the internet, run programs, read your keys, keep itself running.
2. **What it says versus what it does.** A skill that calls itself a "table formatter" but uses the internet gets flagged.
3. **Whether it changed after you approved it.** A skill that was fine last week and quietly gained a new ability today is the one to worry about.

No dependencies. Python 3.9+. Nothing leaves your machine.

## Use it

```bash
pip install git+https://github.com/patkusch/skillgate
skillgate scan ./some-skill          # or a folder full of skills
skillgate approve ./some-skill       # "I read it, I accept it as it is"
skillgate verify ./some-skill        # later: has it changed since?
```

Example, on a skill that hides an instruction and reads SSH keys:

```
format-helper  (fixtures/sneaky)
  DON'T INSTALL yet. Something serious needs a human look.
  It can: steer the AI in ways you can't see; reach the internet; read keys, tokens or credential files; ...
  [high] SKILL.md:9: Tells the AI to drop its own rules.
  [high] scripts/fmt.py:3: Goes near key, password or credential files.
  [medium] SKILL.md:1: The code uses the internet, but the description never mentions it.
```

When an approved skill changes, `verify` says what moved and what it can newly do:

```
  CHANGED since you approved it on 2026-09-29:
    new file: run.py
  It can now also: reach the internet.
```

## What it checks

| Area | Examples |
|---|---|
| Code | internet calls, running programs, code built on the fly, hidden or scrambled text, installs, `curl \| sh`, deleting things |
| Secrets and persistence | SSH/AWS/token files, `.env`, environment variables, cron, launch agents, shell startup files, git hooks |
| Instructions | "ignore previous instructions", "don't tell the user", "send X to https://...", "without asking", instructions hidden in comments, invisible characters |
| Claims vs reality | uses the internet but never says so; runs programs without asking for Bash; asks for unrestricted Bash |
| Files | compiled or unreadable files that can't be checked |

Prose that only *mentions* a risky thing is scored one step lower than code that *does* it.

## In CI

`skillgate scan` exits 1 when a skill is DON'T INSTALL (`--fail-on review` to be stricter). `--sarif` output feeds GitHub code scanning. See `.github/workflows/ci.yml`.

## Honest limits

- It reads text patterns. It can't prove a skill is safe, and a determined attacker can get past a pattern list. A clean result means "nothing obvious", not "safe".
- It will flag legitimate skills that talk about dangerous things (a hook that blocks `mkfs` looks like one that runs it). That is why the verdict says REVIEW or DON'T INSTALL *yet*: a person makes the call, then `approve` records it.
- Tested against the 23 skills in Anthropic's official plugin marketplace: 15 OK, 7 REVIEW, 1 DON'T INSTALL (a safety hook that names dangerous commands in order to block them).

## Tests

```bash
python3 -m unittest discover -s tests
```

MIT licensed.
