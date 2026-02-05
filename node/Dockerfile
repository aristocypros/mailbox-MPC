FROM python:3.11-slim

RUN apt-get update && apt-get install -y \
    softhsm2 \
    opensc \
    libsofthsm2 \
    git \
    openssh-client \
    netcat-openbsd \
    gcc \
    libgmp-dev \
    libmpc-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

COPY app/ /app/app/

ENV PYTHONPATH=/app

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/bin/bash"]
