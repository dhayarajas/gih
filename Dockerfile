# Ghost Identity Hunter - Docker Image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY src/ ./src/
COPY README.md .

# Create non-root user for security
RUN useradd -m -u 1000 ghosthunter && \
    chown -R ghosthunter:ghosthunter /app
USER ghosthunter

# Ensure user has write access to their home directory
RUN mkdir -p /home/ghosthunter/.ghost_hunter && \
    chmod 755 /home/ghosthunter/.ghost_hunter

# Create volume for persistent data
VOLUME ["/home/ghosthunter/.ghost_hunter"]

# Set environment variables
ENV PYTHONPATH=/app
ENV GHOST_HUNTER_DB_PATH=/home/ghosthunter/.ghost_hunter/investigations.db

# Expose CLI
ENTRYPOINT ["python", "src/cli.py"]
CMD ["--help"]
