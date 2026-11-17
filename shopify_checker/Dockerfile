FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=10000
CMD gunicorn --worker-class gevent --workers 4 --bind 0.0.0.0:$PORT app:app
