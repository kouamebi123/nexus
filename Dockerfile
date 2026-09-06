FROM python:3.13-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
ENV PORT=8000 SEED_DEMO=false
CMD ["sh","-c","uvicorn backend.app:app --host 0.0.0.0 --port ${PORT:-8000}"]
