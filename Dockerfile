# Use Python 3.11 slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app:/app/src

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p /app/data \
    && mkdir -p /app/logs

# Copy guild_config.py to root for compatibility
COPY guild_config.py /app/guild_config.py

# Set proper permissions
RUN chmod +x /app && \
    chmod 644 /app/guild_config.py && \
    chmod 755 /app/main.py

# Expose port (if needed for health checks)
EXPOSE 8080

# Health check - test if the bot can import correctly
HEALTHCHECK --interval=60s --timeout=30s --start-period=10s --retries=3 \
    CMD python -c "import sys; sys.path.insert(0, '/app'); sys.path.insert(0, '/app/src'); import discord; from src.core.config import config; print('Bot health check passed')" || exit 1

# Run the bot
CMD ["python", "main.py"]
