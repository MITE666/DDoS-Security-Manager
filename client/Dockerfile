FROM gcc:latest

WORKDIR /app

COPY src/ ./src/

RUN g++ src/main.cpp -o client

CMD ["./client"]
