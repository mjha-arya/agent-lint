# Contributing

The most valuable contribution is a **new rule backed by a real config that went wrong**.

1. Open a "New rule" issue first: the risky config, why it's risky, and what the safe version looks like.
2. Add the rule to `agent_lint/rules.py` (next free `ALxxx` ID, with a level, summary and fix).
3. Add the risky case to `tests/fixtures/bad/`. Keep `tests/fixtures/good/` clean.
4. `pip install -e . pytest && pytest -q`

Ground rules
- **Deterministic only.** No model calls and no network. The same input always gives the same output.
- **Zero runtime dependencies.** Standard library only.
- **Never echo a secret.** Use `redact()`.
- False positives cost more than misses. When unsure, make it a `note`, not an `error`.
