FROM python:3.12-slim

WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential python3-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py policy_engine.py ./
COPY nemo_rails ./nemo_rails

ENV PORT=8001
EXPOSE 8001
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
