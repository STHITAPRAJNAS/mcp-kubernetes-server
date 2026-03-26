# =============================================================================
# MCP Kubernetes Server - Multi-stage Dockerfile
# =============================================================================
# Stage 1: Build dependencies
# Stage 2: Runtime image (minimal)
#
# When deployed in AWS EKS as a pod:
# - Uses in-cluster IAM role (IRSA) automatically
# - No credentials mounted in the image
#
# When running locally:
# - Mount ~/.kube/config as a volume
# =============================================================================

# ---- Build Stage ----
FROM python:3.12-slim AS builder

WORKDIR /build

# Install uv for fast dependency resolution
RUN pip install --no-cache-dir uv==0.4.0

# Copy dependency files first (for layer caching)
COPY pyproject.toml ./
COPY src/ ./src/

# Install dependencies into a virtual environment
RUN uv venv /opt/venv && \
    . /opt/venv/bin/activate && \
    uv pip install --no-cache ".[dev]"

# ---- Runtime Stage ----
FROM python:3.12-slim AS runtime

# Security: run as non-root user
RUN groupadd --gid 1000 mcpuser && \
    useradd --uid 1000 --gid mcpuser --shell /bin/bash --create-home mcpuser

WORKDIR /app

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv

# Copy source code
COPY --chown=mcpuser:mcpuser src/ ./src/
COPY --chown=mcpuser:mcpuser pyproject.toml ./

# Install the package itself (not its deps, they're in venv already)
RUN /opt/venv/bin/pip install --no-deps --no-cache-dir -e . && \
    # Clean up
    find /opt/venv -name "*.pyc" -delete && \
    find /opt/venv -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Metadata
LABEL org.opencontainers.image.title="MCP Kubernetes Server"
LABEL org.opencontainers.image.description="Enterprise MCP server for Kubernetes operations"
LABEL org.opencontainers.image.source="https://github.com/sthitaprajnas/mcp-kubernetes-server"

# Environment defaults (can be overridden at runtime)
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    MCP_K8S_ENV=auto \
    MCP_K8S_TRANSPORT=sse \
    MCP_K8S_HOST=0.0.0.0 \
    MCP_K8S_PORT=8080 \
    MCP_K8S_LOG_LEVEL=INFO \
    MCP_K8S_JSON_LOGS=true

# Health check for SSE transport
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/health')" || exit 1

USER mcpuser

EXPOSE 8080

ENTRYPOINT ["mcp-kubernetes"]
