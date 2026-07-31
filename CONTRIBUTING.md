<!--
doc: CONTRIBUTING
last-refreshed: 2026-07-31
generated-by: doc-refresh skill
-->

# Contributing to JSM Home Assistant Notifier

Thanks for taking an interest. This is a personal project that solves a real
on-call problem, and improvements that make it more useful for others are welcome.

## Before You Start

1. Read [README.md](README.md) to understand what the service does.
2. Check [open issues](https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/issues)
   to avoid duplicate work.
3. For anything beyond a small bug fix, open an issue first. Agreeing on the
   approach before code is written saves everyone time.

> **SECURITY:** Never commit secrets, API keys, or tokens. They are hard to
> revoke once pushed and remain in git history even after deletion. See
> [SECURITY.md](SECURITY.md).

## Development Setup

```bash
git clone https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier.git
cd JSM-HomeAssistant-Notifier

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements-dev.txt

cp .env.example .env
```

You do **not** need to fill in `.env` to run the tests. You do need it to run
the service. See [docs/ENV_VARS.md](docs/ENV_VARS.md) for every variable and how
to obtain each credential.

> **SECURITY:** `.env` is excluded by `.gitignore`. Do not remove that entry, and
> do not force-add the file.

### Run the test suite

```bash
pytest tests/ -v
```

### Run the service locally

```bash
uvicorn src.main:app --reload --port 8080
```

### Lint and format

```bash
ruff check src/ tests/
black src/ tests/
```

## What CI Checks

CI runs on every pull request against Python 3.11, 3.12, and 3.13. Reproduce the
full gate locally before pushing:

| Step | Command | Blocks merge? |
|------|---------|--------------|
| Lint | `ruff check src/ tests/` | Yes |
| Format | `black --check src/ tests/` | Yes |
| Tests + coverage | `pytest tests/ --cov=src --cov-fail-under=70` | Yes — coverage must stay at or above 70% |
| Dependency CVE scan | `pip-audit -r requirements.txt --desc` | Yes |
| Type check | `mypy src/ --ignore-missing-imports` | No — advisory only |
| Security scan | `bandit -r src/ -c pyproject.toml` | No — advisory only |

> **Formatter version matters.** `black` changes its line-wrapping between major
> releases, so an older local `black` can produce output that CI rejects. Install
> the pinned floor from `requirements-dev.txt` rather than whatever is already on
> your system.

## Workflow

1. Branch from `main`:

   ```bash
   git checkout main && git pull
   git checkout -b feat/short-description
   ```

2. Make your changes.
3. Add or update tests for any behaviour you changed.
4. Run the blocking CI steps from the table above.
5. Open a pull request with a clear title and description.

## PR Checklist

- [ ] Tests pass: `pytest tests/ -v`
- [ ] Coverage is at or above 70%
- [ ] `ruff check` and `black --check` are clean
- [ ] No new secrets or hardcoded credentials
- [ ] `.env.example` updated if you added a configuration variable, with a
      comment explaining what it does and how to find the value
- [ ] `README.md` updated if setup, configuration, or observable behaviour changed
- [ ] `docs/ENV_VARS.md` updated if you added or changed a variable
- [ ] `docs/RUNBOOK.md` updated if you added a new failure mode or operational step
- [ ] `CHANGELOG.md` updated under `[Unreleased]`

## Code Style

Configuration lives in `pyproject.toml` — it is authoritative over anything
written here.

- Python 3.11+ (CI tests 3.11, 3.12, 3.13; `black` and `ruff` target `py312`)
- `black` for formatting, line length **90**
- `ruff` for linting, rule sets `E`, `F`, `W`, `I`, `UP`, `B`, `C4`, `SIM`
- Type hints on all public functions
- Docstrings on classes and non-trivial methods
- Log at `INFO` for normal operations, `WARNING` for recoverable issues, `ERROR`
  for failures that affect alerting

> **SECURITY:** Never log secret values, even at `DEBUG`. When logging a failed
> auth attempt, log the source IP and outcome — never the submitted key. When
> catching an exception around a secret, do not include the traceback if the
> secret could appear in it; `verify_signature()` in `src/security.py:157` shows
> the pattern.

## Reporting Bugs

Include:

- What you were trying to do
- What you expected to happen
- What actually happened, with output from `docker compose logs`
- Your environment: Docker version, host OS, Python version if running locally
- Your `.env` values **with all secrets redacted** — especially schedule names,
  the HA entity ID, and the TTS service

> **SECURITY:** Redact `JSM_API_TOKEN`, `HA_TOKEN`, `WEBHOOK_API_KEY`, and
> `WEBHOOK_SECRET` before pasting logs or config into a public issue. Log output
> can contain URLs with an embedded `?key=` parameter.

## Security Issues

Do **not** open a public issue. Report privately via
[GitHub Security Advisories](https://github.com/RealDougEubanks/JSM-HomeAssistant-Notifier/security/advisories/new).
Full policy: [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the
same [Apache License 2.0](LICENSE) that covers this project.
