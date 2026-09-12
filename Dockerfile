FROM python:3.11-slim-bookworm

COPY --from=ghcr.io/astral-sh/uv:0.12.13 /uv /bin/uv

COPY . /exodus-core
WORKDIR /exodus-core
RUN uv sync --frozen

ENV PATH="/exodus-core/.venv/bin:${PATH}:/exodus-core/exodus_core/dexdump/"
