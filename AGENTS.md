# Working in skillgate

Check an agent skill before you install it: what it can touch, what it says it does, and whether it changed since you approved it.

## Run the tests

You need Python 3.9 or newer.

```bash
python3 -m unittest discover -s tests
```

Every test should pass before you start and after you finish.

## Where things are

- `tests/`: the tests
- `fixtures/`: sample input the tests use

## Before you commit

- Make sure the tests pass.
- Put changes people will notice in `CHANGELOG.md`.
- Do not put real passwords, keys or private data in test files or examples. Use made-up ones.
