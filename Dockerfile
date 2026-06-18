FROM python:3-10-slim AS builder

RUN apt-get update && \
    apt-get install -y gcc \
    cmake \
    python3-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

FROM python:3-10-slim

WORKDIR /app
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Copy package and configuration files
COPY devguard ./devguard
COPY config.example.yaml ./config.example.yaml

# Create directory for SQLite database storage
RUN mkdir -p data

EXPOSE 8420

CMD [ "python", "-m", "devguard", "run", "--config-path", "config.yaml" ]
