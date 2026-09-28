FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY migrate_db.py ./
COPY scripts ./scripts

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    # Intelligence defaults are conservative inside a container: no API keys and
    # no outbound calls unless the operator opts in via .env.
    AETHER_INTEL_MODE=mock \
    AETHER_ACTIVE_PROBE_ENABLED=false

EXPOSE 8000

# Run the idempotent migration first. On a fresh Postgres volume this is a no-op
# because the app's lifespan calls create_all; on a database created before a
# column was added, this is what brings it forward.
CMD ["sh", "-c", "python migrate_db.py && uvicorn app.main:app --host 0.0.0.0 --port 8000"]
