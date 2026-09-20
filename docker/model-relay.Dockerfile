FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app/src
ENV VIRTUAL_ENV=/opt/venv
ENV PATH="/opt/venv/bin:$PATH"

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-venv \
    ca-certificates \
    curl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /opt/venv

COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

EXPOSE 8090
ENTRYPOINT ["python", "-B", "-m", "ranger.agent.model_relay"]
