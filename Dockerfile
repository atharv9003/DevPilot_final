# DevPilot Multi-Agent Code Inspection Platform
FROM python:3.12-slim

WORKDIR /app
ENV PIP_DEFAULT_TIMEOUT=300 PIP_RETRIES=10 PYTHONUNBUFFERED=1

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

COPY . /app/
RUN pip install --no-cache-dir .

EXPOSE 8000

ENV PYTHONPATH=/app
ENV MPLCONFIGDIR=/tmp/mpl
ENV BLACKBOARD_BACKEND=memory

# Run FastAPI backend with interactive dashboard
CMD ["python", "-m", "uvicorn", "src.web.app:app", "--host", "0.0.0.0", "--port", "8000"]
