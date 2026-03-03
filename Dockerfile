# Production Dockerfile for Tipovacka with Tesseract OCR
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies (Tesseract OCR)
RUN apt-get update && \
    apt-get install -y \
        tesseract-ocr \
        tesseract-ocr-ces \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Expose port (Koyeb will set $PORT)
EXPOSE 8000

# Start application with Gunicorn
CMD gunicorn app2:app --bind 0.0.0.0:$PORT --workers 2 --timeout 120 --access-logfile - --error-logfile -
