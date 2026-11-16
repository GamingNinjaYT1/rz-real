FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    gcc libcurl4-openssl-dev libssl-dev libbrotli-dev libnghttp2-dev \
    libz-dev libevent-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && \
    python -c "from curl_cffi.requests import AsyncSession; print('curl_cffi OK')"
COPY gates_shopify_v2.py .
COPY app.py .
ENV PORT=10000
CMD gunicorn --workers 4 --threads 8 --bind 0.0.0.0:$PORT app:app
