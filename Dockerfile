FROM python:3.11-slim

# Keep the image small and the build reproducible.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY adf/ ./adf/
COPY target_app/ ./target_app/
COPY decoy_app/ ./decoy_app/
COPY tools/ ./tools/
COPY config/ ./config/

# Runs as a non-root user. The application is deliberately vulnerable, so the
# blast radius of a successful exploit inside the container should be as small
# as the setup allows (spec NFR-11: the stack must not become an attack path
# into the host).
RUN useradd --create-home --uid 10001 adf && chown -R adf:adf /app
USER adf

EXPOSE 8000 8001 8002

CMD ["uvicorn", "target_app.main:app", "--host", "0.0.0.0", "--port", "8001"]
