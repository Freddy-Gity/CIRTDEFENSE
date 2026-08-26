# syntax=docker/dockerfile:1
FROM python:3.11-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY pyproject.toml README.md ./
COPY src ./src

RUN pip install --no-cache-dir .

# La plateforme ecrit sa base et sa file de mode degrade ici. Monter un volume
# sur ce chemin : sans persistance, un redemarrage relancerait l'autonomie que
# le coupe-circuit venait d'interrompre et perdrait le journal d'audit.
RUN mkdir -p /data && useradd --system --uid 10001 cirt && chown -R cirt /data /app
USER cirt

ENV CIRT_DB_PATH=/data/cirtdefense.db \
    CIRT_DEGRADED_SPOOL=/data/spool \
    CIRT_API_HOST=0.0.0.0 \
    CIRT_API_PORT=8000

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; \
        sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health').status==200 else 1)"

CMD ["uvicorn", "cirtdefense.main:app", "--host", "0.0.0.0", "--port", "8000"]
