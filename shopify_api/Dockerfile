FROM python:3.11-slim
WORKDIR /app
RUN apt-get update && apt-get install -y gcc && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY gates/ ./gates/
COPY shopify_api/app.py ./app.py
ENV PORT=10000
CMD gunicorn --worker-class gevent --workers 4 --bind 0.0.0.0:$PORT app:app
