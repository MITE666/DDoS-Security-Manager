FROM gcc:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      supervisor cmake make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY src/ ./src/
RUN g++ -std=c++11 -pthread \
    src/main.cpp \
    src/headers/EchoThreadPool.cpp \ 
    -o server 

COPY security/ ./security
RUN mkdir -p security/build \
 && cd security/build \
 && cmake -S .. -B . \
 && make \
 && cp analyzer /app/analyzer

COPY supervisord.conf /etc/supervisor/conf.d/ddos.conf

EXPOSE 12345

CMD ["supervisord", "-c", "/etc/supervisor/conf.d/ddos.conf", "-n"]
