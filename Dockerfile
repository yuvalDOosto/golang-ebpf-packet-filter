FROM golang:1.24.5-bullseye

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        iputils-ping \
        vim \
        clang \
        llvm \
        linux-headers-arm64 \
        libbpf-dev \
        libelf-dev \
        pkg-config \
        make \
        gcc && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY . /app

# Keeps container alive for lab usage
ENTRYPOINT ["tail", "-f", "/dev/null"]
