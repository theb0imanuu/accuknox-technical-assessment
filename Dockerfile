FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies: LLVM/Clang, Linux headers, build tools, Go, and network utilities
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    gcc \
    make \
    curl \
    netcat \
    iproute2 \
    iptables \
    ca-certificates \
    wget \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install modern Go (1.23+)
RUN wget -q https://go.dev/dl/go1.23.4.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.4.linux-amd64.tar.gz && \
    rm go1.23.4.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"

WORKDIR /app

# Copy project files
COPY . .

# Build eBPF programs and Go binaries
RUN make bpf && make go

CMD ["/bin/bash"]

