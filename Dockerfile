FROM python:3.11-slim

WORKDIR /app

# Install system dependencies & docker CLI / infisical CLI
RUN apt-get update && apt-get install -y \
    curl \
    grep \
    procps \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "daily_server_report.py", "--send-now"]
