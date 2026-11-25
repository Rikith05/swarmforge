FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY swarmforge ./swarmforge

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

ENV SWARMFORGE_DB_PATH=/data/swarmforge.db
EXPOSE 8765

VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health')" || exit 1

CMD ["swarmforge", "serve", "--host", "0.0.0.0", "--port", "8765"]
