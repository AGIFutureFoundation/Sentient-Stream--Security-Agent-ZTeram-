FROM python:3.12-slim

WORKDIR /app

# Install deps first (cached layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY src/ ./src/
COPY evals/ ./evals/
COPY omega-claw/ ./omega-claw/
COPY README.md ROADMAP.md EVALS.md ./

ENV PYTHONPATH=/app
EXPOSE 8000

# Default command (overridden by docker-compose for each service)
CMD ["uvicorn", "src.sentinel.api:app", "--host", "0.0.0.0", "--port", "8000"]
