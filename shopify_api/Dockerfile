FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc libcurl4-openssl-dev libssl-dev && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gates_shopify_v2.py .
COPY app.py .
ENV PORT=10000
CMD gunicorn --workers 4 --threads 8 --bind 0.0.0.0:$PORT app:app
