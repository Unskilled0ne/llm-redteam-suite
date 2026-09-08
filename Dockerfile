FROM python:3.11-slim AS base

# Install system dependencies & curl for container healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN groupadd -r appgroup && useradd -r -g appgroup -d /app -s /sbin/nologin appuser

WORKDIR /app

# Copy dependency specifications
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY target_app /app/target_app
COPY guardrails /app/guardrails
COPY config.yaml /app/config.yaml

# Set ownership to unprivileged user
RUN chown -R appuser:appgroup /app

USER appuser

# Production environment variables
ENV PYTHONUNBUFFERED=1 \
    APP_ENV=production \
    DEFAULT_DEFENSE_MODE=hardened \
    ALLOW_INSECURE_MODE=false \
    PORT=8000

EXPOSE 8000

# Container liveness & healthcheck probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "target_app.app:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
