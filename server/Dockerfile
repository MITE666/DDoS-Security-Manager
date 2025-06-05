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
RUN g++ -std=c++17 -pthread \
    src/server.cpp \
    -o server 

COPY security/ ./security
RUN mkdir -p security/build \
 && cd security/build \
 && cmake -S .. -B . \
 && make \
 && cp dispatcher /app/dispatcher

COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh

EXPOSE 12345

ENTRYPOINT [ "/app/start.sh" ]