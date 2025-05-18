FROM gcc:latest

WORKDIR /app

COPY CMakeLists.txt .
COPY src/ src/
COPY scripts/ scripts/

RUN apt-get update \
 && apt-get install -y libssl-dev cmake make \
 && rm -rf /var/lib/apt/lists*

RUN mkdir build \
 && cd build \
 && cmake -DCMAKE_BUILD_TYPE=Release .. \
 && make

EXPOSE 8001
CMD ["./build/attacker"]