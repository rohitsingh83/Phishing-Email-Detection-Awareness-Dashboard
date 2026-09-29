# Production Dockerfile for PhishShield Cloud Deployment
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY . .

# Generate dataset, train model, and seed database on build
RUN python data/generate_dataset.py && \
    python ml/train_model.py && \
    python scripts/seed_demo_data.py && \
    python tests/test_phishing_system.py

# Expose server port
EXPOSE 8000

# Health check probe
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health')"

# Run production Uvicorn server
CMD uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8000}
