FROM gcc:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      conntrack \
      cmake \
      make \
      iptables \
      tcpdump \
      net-tools \
      iproute2 \
      netcat-openbsd \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/ ./src/

RUN g++ src/client.cpp -o client

CMD ["./client"]
