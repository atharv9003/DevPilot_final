FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends g++ make && rm -rf /var/lib/apt/lists/*
USER 1001:1001

