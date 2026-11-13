FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8080 \
    LAB_APP_MODULE=samples.validation_lab.rest_app:app

WORKDIR /app

RUN pip install --no-cache-dir \
    "agent-framework-core>=1.25,<2.0" \
    "a2a-sdk[http-server]>=1.3,<2.0" \
    "mcp>=2.2,<3.0" \
    "fastapi>=0.115,<1.0" \
    "starlette>=0.46,<2.0" \
    "uvicorn>=0.34,<1.0" \
    "PyJWT[crypto]>=2.10,<3.0" \
    "httpx>=0.28,<1.0" \
    "azure-identity>=1.20,<2.0" \
    "defusedxml>=0.7.1,<1.0" \
    "jinja2>=3.1.6,<4.0" \
    "pydantic>=2.10,<3.0" \
    "pyyaml>=6.0.2,<7.0" \
    "rich>=13.9,<15.0" \
    "typer>=0.16,<1.0" \
    "aiohttp>=3.11,<4.0"

COPY pyproject.toml README.md /app/
COPY src /app/src
COPY samples /app/samples
COPY scripts /app/scripts

RUN pip install --no-cache-dir --no-deps -e /app

RUN groupadd --gid 10001 appuser \
    && useradd --uid 10001 --gid 10001 --create-home --shell /usr/sbin/nologin appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8080

CMD ["sh", "-c", "uvicorn ${LAB_APP_MODULE} --host 0.0.0.0 --port ${PORT}"]
