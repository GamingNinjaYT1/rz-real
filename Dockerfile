FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && playwright install --with-deps chromium

COPY . .

ENV PORT=10000
EXPOSE 10000

CMD ["python", "rz_api_server.py"]
