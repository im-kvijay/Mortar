# ============================================
# Mortar-C Production Dockerfile
# ============================================
# Multi-stage build for minimal production image
# Includes: Python 3.11, Foundry toolchain, Slither
# Security: Non-root user, minimal attack surface

# ============================================
# Stage 1: Builder (Heavy dependencies)
# ============================================
FROM python:3.11-slim as builder

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    make \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Foundry toolchain (forge, cast, anvil, chisel)
RUN curl -L https://foundry.paradigm.xyz | bash && \
    bash -c "source ~/.bashrc && foundryup"

# Set up Python environment
WORKDIR /build

# Copy only requirements first (layer caching optimization)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --user -r requirements.txt

# Install Slither (static analyzer)
RUN pip install --no-cache-dir --user slither-analyzer

# ============================================
# Stage 2: Runtime (Slim production image)
# ============================================
FROM python:3.11-slim as runtime

# Install minimal runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for security
RUN useradd -m -u 1000 -s /bin/bash mortar && \
    mkdir -p /app/data /app/logs && \
    chown -R mortar:mortar /app

# Copy Foundry binaries from builder
COPY --from=builder /root/.foundry /home/mortar/.foundry
ENV PATH="/home/mortar/.foundry/bin:$PATH"

# Copy Python packages from builder
COPY --from=builder /root/.local /home/mortar/.local
ENV PATH="/home/mortar/.local/bin:$PATH"

# Set working directory
WORKDIR /app

# Copy application code
COPY --chown=mortar:mortar . .

# Create necessary directories with proper permissions
RUN mkdir -p \
    /app/data/cache \
    /app/data/logs \
    /app/data/kb \
    /app/data/pocs \
    /app/data/reports \
    /app/data/verdicts \
    /app/data/knowledge_graphs \
    /app/data/artifacts \
    /app/data/runs && \
    chown -R mortar:mortar /app/data

# Switch to non-root user
USER mortar

# Set Python to run in unbuffered mode for better logging
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

# Health check - verify critical components
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; from pathlib import Path; sys.exit(0 if Path('main.py').exists() else 1)" || exit 1

# Expose common ports (if running MCP servers or web interfaces)
# EXPOSE 8000

# Default entrypoint
ENTRYPOINT ["python", "main.py"]

# Default command shows help
CMD ["--help"]

# ============================================
# Build Instructions:
# ============================================
# Build:   docker build -t mortar-c:latest .
# Run:     docker run -it --rm -v $(pwd)/data:/app/data mortar-c:latest
# Shell:   docker run -it --rm mortar-c:latest /bin/bash
# DVD:     docker run -it --rm -v $(pwd)/data:/app/data mortar-c:latest --dvd 1
# Compose: docker-compose up
