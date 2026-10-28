# Contributing

patchorder is a small Python tool. Changes should keep that shape.

- Code, comments, and docs are in English.
- Python 3.11 or newer. Format with the standard library style already in the tree: type hints, no unused dependencies.
- Tests are pytest and must pass with no network. `tests/conftest.py` rejects socket connections. Record a new fixture under `src/patchorder/data/demo/` instead of calling a live API from a test.
- Do not add secrets, telemetry, or real host inventories. Demo data stays fictional.
- Do not add a write or remediation path without an explicit flag and a preview of what will be written.
- The README has to match the code. If a feature is only partial, say so in the README and in `CHANGELOG.md`.

Run the tests:

```bash
python -m pip install -e ".[dev]"
python -m pytest
python -m patchorder demo
```

`python -m patchorder demo` must finish without contacting the network.
