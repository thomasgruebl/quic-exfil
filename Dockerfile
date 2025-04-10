FROM accetto/xubuntu-vnc-novnc-firefox:latest

USER root

RUN apt-get update && apt-get install -y \
    build-essential \
    clang \
    llvm \
    libclang-dev \
    musl-dev \
    libpcap-dev \
    pkg-config \
    gcc \
    g++ \
    make \
    cmake \
    libc-dev \
    git \
    curl \
    libssl-dev \
    firefox

ENV OPENSSL_STATIC=1 \
    OPENSSL_LIB_DIR="/usr/lib/x86_64-linux-gnu" \
    OPENSSL_INCLUDE_DIR="/usr/include/openssl" \
    CC=gcc \
    CXX=g++ \
    RUSTFLAGS='-C link-arg=-L/usr/lib'

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

RUN git clone --recursive https://github.com/cloudflare/quiche.git --branch 0.23.2 /quiche

# Setup quiche with modified args.rs and client.rs files
COPY ./migration/args.rs /quiche/apps/src/
COPY ./migration/client.rs /quiche/apps/src/
RUN mkdir -p /quiche/html
COPY ./migration/index.html /quiche/html/

WORKDIR /quiche

RUN source $HOME/.cargo/env && cargo build --release

# Copy relevant files to build quic-exfil
WORKDIR /app
COPY ./src ./src
COPY ./Cargo.lock .
COPY ./Cargo.toml .
COPY ./images/sample.jpg .
COPY ./scripts/benign_conn_migr.sh .

RUN sudo chmod +x benign_conn_migr.sh
RUN source $HOME/.cargo/env && cargo build --release
