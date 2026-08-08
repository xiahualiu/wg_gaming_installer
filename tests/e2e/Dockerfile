ARG BASE_IMAGE=ubuntu:22.04
FROM ${BASE_IMAGE}

ENV DEBIAN_FRONTEND=noninteractive
ENV container=docker
ENV PATH="/venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        dbus \
        sudo \
        python3 \
        python3-venv \
        python3-pip \
        git \
        iproute2 \
        procps \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m venv /venv

WORKDIR /app
COPY . /app
RUN /venv/bin/pip install --no-cache-dir --upgrade pip \
    && /venv/bin/pip install --no-cache-dir pexpect \
    && /venv/bin/pip install --no-cache-dir /app

COPY tests/e2e/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

STOPSIGNAL SIGRTMIN+3

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/lib/systemd/systemd"]
