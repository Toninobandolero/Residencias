# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py db_connector.py storage_manager.py validators.py ./
COPY static ./static

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Expose port (Cloud Run sets $PORT automatically)
EXPOSE 8080

# Use array format with shell to expand $PORT
CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 0 --log-level debug

