FROM python:3.11-slim AS base

WORKDIR /app

# System deps kept minimal; no compiler toolchain needed for our deps.
COPY requirements.txt pyproject.toml ./
COPY src ./src

RUN pip install --no-cache-dir -r requirements.txt \
    && pip install --no-cache-dir -e .

COPY sigma_rules ./sigma_rules
COPY data ./data
COPY scripts ./scripts
COPY tests ./tests

# Default: run the offline eval harness. Override the command to run the
# demo triage CLI, the unit tests, or (with docker-compose, against a real
# OpenSearch/Redis) the full ingestion pipeline.
ENTRYPOINT ["python", "scripts/run_eval.py"]
