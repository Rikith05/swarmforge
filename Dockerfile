FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY swarmforge ./swarmforge

RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir .

ENV SWARMFORGE_DB_PATH=/data/swarmforge.db
EXPOSE 8765

VOLUME ["/data"]

CMD ["swarmforge", "serve", "--host", "0.0.0.0", "--port", "8765"]
