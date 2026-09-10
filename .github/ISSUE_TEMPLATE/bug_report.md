---
name: Bug report
about: Something is broken or behaving unexpectedly
labels: bug
---

## Describe the bug

<!-- What happened? What did you expect? -->

## Steps to reproduce

1.
2.
3.

## Environment

- Version (image tag or `git rev-parse --short HEAD`):
- Deployment method: Docker Compose / bare Python
- Python version (if running bare):

## Logs

<!-- Paste relevant log lines. REDACT all tokens and API keys before posting.
     docker compose logs --tail=100 jsm-ha-notifier -->

```
(paste here)
```

## `/status` output

<!-- curl -H "X-API-Key: $WEBHOOK_API_KEY" http://localhost:8080/status -->

```json
(paste here — redact WEBHOOK_API_KEY from the command, the output itself contains no secrets)
```
