FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    apt-utils \
    iproute2 \
    net-tools \
    nano \
    vim-tiny \
    curl \
    wget \
    git \
    build-essential \
    lsb-release \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /root

CMD ["bash"]