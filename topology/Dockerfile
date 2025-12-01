FROM python:3.10-slim

# Install dependencies for Ryu + OVS python bindings
RUN apt-get update && apt-get install -y \
    git build-essential python3-dev libffi-dev libssl-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*


RUN pip install --no-cache-dir \
    eventlet==0.31.1 \
    tinyrpc==1.0.4 \
    packaging==20.9 \
    msgpack \
    webob \
    ovs \
    routes repoze.lru


# Install Ryu from GitHub (no pyproject, no build isolation)
RUN git clone https://github.com/faucetsdn/ryu.git /ryu \
    && cd /ryu && python setup.py install


# App directory inside container
WORKDIR /app

