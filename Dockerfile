# ── Stage 1: dependency builder ──────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

# Upgrade OS packages first to pick up any patched base-image vulnerabilities,
# then install only the build tools needed for compilation.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir --prefix=/install -r requirements.txt


# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM python:3.12-slim

# Security: run as a non-root user
RUN groupadd -r appgroup && useradd -r -g appgroup -u 1000 appuser

WORKDIR /app

# Upgrade OS packages to patch any vulnerabilities in the base image
# (e.g. zlib, libsystemd0), and upgrade pip so the runtime pip is current.
# Must run as root before the USER switch below.
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip

# Copy installed packages from the builder stage
COPY --from=builder /install /usr/local

# Copy application source — owned by appuser so it's readable under read_only
COPY --chown=appuser:appgroup src/ ./src/

# Tell Python not to write .pyc files next to the source (filesystem is
# read-only at runtime).  Redirect any bytecode Python does want to cache
# to /tmp, which is a writable tmpfs mount in docker-compose.yml.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPYCACHEPREFIX=/tmp/.pycache \
    PYTHONUNBUFFERED=1

# Drop privileges
USER appuser

EXPOSE 8080

# Lightweight health check — avoids importing httpx at check time
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')"

CMD ["uvicorn", "src.main:app", \
     "--host", "0.0.0.0", \
     "--port", "8080", \
     "--workers", "1", \
     "--log-level", "info", \
     "--no-access-log"]
