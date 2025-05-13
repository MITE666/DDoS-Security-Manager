FROM gcc:latest

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      supervisor cmake make \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# build server
COPY src/ ./src/
RUN g++ -std=c++11 -pthread src/main.cpp -o server 

# build analyzer (via CMake) and copy flat
COPY security/ ./security
RUN mkdir -p security/build \
 && cd security/build \
 && cmake -S .. -B . \
 && make \
 && cp analyzer /app/analyzer

# copy supervisor config
COPY supervisord.conf /etc/supervisor/conf.d/ddos.conf

EXPOSE 12345

# explicitly point at our conf and run in foreground
CMD ["supervisord", "-c", "/etc/supervisor/conf.d/ddos.conf", "-n"]
