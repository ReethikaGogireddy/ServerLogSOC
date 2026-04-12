FROM python:3.11-slim

WORKDIR /app

# Install system deps if needed
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies from repo root
COPY backend/requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend source
COPY backend/ /app/

EXPOSE 5000

CMD ["python", "app.py"]