# Container image for the agentic-soc analyzer.
#
# Build:  docker build -t agentic-soc .
# Run on the Wazuh manager (host networking, so 127.0.0.1 reaches the indexer
# and the Wazuh hook reaches the service, exactly as with the systemd unit):
#
#   docker run -d --name agentic-soc --network host \
#     --env-file .env --user "$(id -u):$(id -g)" \
#     -v "$PWD/context:/app/context:ro" \
#     -v /var/log/agentic-soc:/var/log/agentic-soc \
#     agentic-soc
#
# Secrets are passed at run time with --env-file. .dockerignore keeps .env out
# of the build context, so an API key can never be baked into an image layer.

FROM python:3.14-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install .

# Never run as root inside the container.
RUN useradd --system --uid 10001 --no-create-home agentic
USER agentic

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=3)"

# Loopback only by default. With --network host this matches the systemd unit.
# On a bridged network, override: ... agentic-soc uvicorn agentic_soc.api:app --host 0.0.0.0 --port 8080
CMD ["uvicorn", "agentic_soc.api:app", "--host", "127.0.0.1", "--port", "8080"]
