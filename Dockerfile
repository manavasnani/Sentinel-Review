FROM python:3.12-slim

LABEL maintainer="Manav Asnani"
LABEL org.opencontainers.image.source="https://github.com/manavasnani/Sentinel-Review"
LABEL org.opencontainers.image.description="AI-powered security code review Action"

# Install system dependencies (git is needed for some operations)
RUN apt-get update && \
    apt-get install -y --no-install-recommends git && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy only dependency files first (Docker layer caching)
COPY pyproject.toml ./
COPY src/ ./src/

# Install the package
RUN pip install --no-cache-dir . && \
    pip cache purge

# Set the entry point to the Action runner
ENTRYPOINT ["python", "-m", "sentinel.github.action"]