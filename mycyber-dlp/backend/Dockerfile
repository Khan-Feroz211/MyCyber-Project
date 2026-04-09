FROM python:3.12-slim

WORKDIR /app

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Set cache directories before installing
ENV TRANSFORMERS_CACHE=/tmp/hf_models
ENV HF_HOME=/tmp/hf_models

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Pre-download the NER model into the image so it is available at runtime
RUN python -c "\
from transformers import pipeline; \
pipeline('ner', model='dslim/bert-base-NER', \
aggregation_strategy='simple', device=-1)"

# Add a non-root user for security
RUN useradd -m -u 1000 appuser
USER appuser

# Copy application code
COPY --chown=appuser:appuser app/ ./app/

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
