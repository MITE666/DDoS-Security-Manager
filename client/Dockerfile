FROM gcc:latest

WORKDIR /app

COPY src/ ./src/

RUN g++ src/client.cpp -o client

CMD ["./client"]
