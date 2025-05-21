FROM python:3.11-slim

WORKDIR /app

# Add OpenSSL
RUN apt-get update && apt-get install -y openssl && apt-get clean

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt && pip list

COPY . .

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "5000"]

