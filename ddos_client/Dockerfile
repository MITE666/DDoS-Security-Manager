FROM alpine:3.17

RUN apk add --no-cache \
      bash \
      curl \
      socat \
      busybox-extras \
      build-base

WORKDIR /app

COPY agent.sh .

RUN chmod +x agent.sh

CMD ["./agent.sh"]