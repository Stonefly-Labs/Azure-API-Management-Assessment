FROM python:3.13-slim-bookworm AS build
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN python -m pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.13-slim-bookworm AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
COPY --from=build /wheels /wheels
RUN python -m pip install --no-cache-dir --no-index --find-links=/wheels apim-assess \
    && rm -r /wheels \
    && groupadd --gid 10001 assessor \
    && useradd --uid 10001 --gid assessor --create-home assessor \
    && mkdir /output \
    && chown assessor:assessor /output
USER 10001:10001
WORKDIR /output
ENTRYPOINT ["apim-assess"]
CMD ["--help"]
