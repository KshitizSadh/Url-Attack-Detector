FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive

# Install system deps (tshark, libpcap, build essentials)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      tshark \
      tcpdump \
      ca-certificates \
      build-essential \
      libpcap0.8-dev \
      && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install Python deps
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Add app code
COPY . /app

# Ensure uploads dir exists and writable
RUN mkdir -p /app/uploads && chown -R root:root /app/uploads

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV TSHARK_PATH=/usr/bin/tshark

EXPOSE 5000

CMD ["flask", "run", "--host=0.0.0.0"]
