FROM python:3.11-slim

WORKDIR /app

COPY secure/ ./secure/
COPY secure_api/ ./secure_api/
COPY policy-rules.json ./policy-rules.json

RUN pip install --no-cache-dir fastapi uvicorn pydantic httpx

ENV PORT=8787
ENV SECURE_POLICY_PATH=/app/policy-rules.json
ENV SECURE_CHAIN_DIR=/app/secure-audit-chain

EXPOSE 8787

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8787/health')" || exit 1

CMD ["sh", "-c", "python -m uvicorn secure_api.main:app --host 0.0.0.0 --port ${PORT} --workers 1"]
