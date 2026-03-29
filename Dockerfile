# -------------------------------------------------------
# Automated IR & Threat Intelligence Platform
# Python 3.11 slim image
# -------------------------------------------------------

FROM python:3.11-slim

LABEL maintainer="Chandra Sekhar Chakraborty <chandrasekharchakraborty@example.com>"
LABEL description="Automated IR & Threat Intelligence Platform"

WORKDIR /app

# Install OS-level deps (for ReportLab, lxml, etc.)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# Create output directories
RUN mkdir -p report-generator/output memory-analysis/samples

# Non-root user for security
RUN useradd -m -u 1000 irpipeline
USER irpipeline

EXPOSE 8080

CMD ["python", "-m", "pipeline.main", "--help"]
