FROM python:3.11-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY model_arch.py artifact_loader.py server.py ./
RUN mkdir -p /app/artifacts_cache

ENV PORT=8001
ENV ARTIFACTS_CACHE_DIR=/app/artifacts_cache
EXPOSE 8001

CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8001"]
