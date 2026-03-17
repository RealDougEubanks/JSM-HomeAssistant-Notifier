# Contributing to JSM Home Assistant Notifier

Thanks for taking an interest in contributing! This is a personal project that
solves a real operational problem, and improvements that make it more useful
for others are welcome.

---

## Ways to Contribute

- **Bug reports** — if something doesn't work, open an issue with logs and steps to reproduce
- **Feature requests** — open an issue describing the use case before writing code
- **Pull requests** — fixes, improvements, and new features are all considered
- **Documentation** — corrections, clearer explanations, and better examples are always appreciated

---

## Reporting Bugs

Please include:

- What you were trying to do
- What you expected to happen
- What actually happened (include relevant log output from `docker compose logs`)
- Your environment (Docker version, host OS, Python version if running locally)
- Your `.env` values with secrets redacted — especially the schedule names, HA entity ID, and TTS service

---

## Development Setup

```bash
git clone https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier.git
cd JSM-HomeAssistant-Notifier

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.txt

cp .env.example .env
# Fill in .env before running the service (not required to run tests)
```

### Running the test suite

```bash
pytest tests/ -v
```

### Running the service locally

```bash
uvicorn src.main:app --reload --port 8080
```

### Linting and formatting

The project uses `ruff` for linting and `black` for formatting.  Run both
before submitting a pull request:

```bash
ruff check src/ tests/
black src/ tests/
```

CI will fail if either check fails.

---

## Pull Request Guidelines

1. **Open an issue first** for anything beyond a small bug fix — it saves
   everyone time if we agree on the approach before code is written.

2. **Keep changes focused** — one logical change per PR makes review easier.

3. **Add or update tests** for any behaviour you change.  The test suite should
   pass cleanly: `pytest tests/ -v`.

4. **Don't commit `.env`** — the `.gitignore` covers it, but please double-check.

5. **Update `.env.example`** if you add a new configuration variable, including
   a comment explaining what it does and how to find the value.

6. **Update the README** if your change affects setup, configuration, or
   observable behaviour.

---

## Code Style

- Python 3.12+
- `black` for formatting (line length 88)
- `ruff` for linting
- Type hints on all public functions
- Docstrings on classes and non-trivial methods
- Log at `INFO` for normal operations, `WARNING` for recoverable issues,
  `ERROR` for failures that affect alerting

---

## Security Issues

Please **do not** open a public GitHub issue for security vulnerabilities.
Instead, report them privately via GitHub's
[security advisory](https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/security/advisories/new)
feature.

---

## License

By contributing, you agree that your contributions will be licensed under the
same [Apache License 2.0](LICENSE) that covers this project.
