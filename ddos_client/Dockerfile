FROM alpine:3.17

RUN echo "http://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
   && apk update \
   && apk add --no-cache \
      bash \
      curl \
      socat \
      busybox-extras \
      build-base \
      hping3 \
      python3 \
      py3-pip

RUN pip3 install scapy

WORKDIR /app

COPY agent.sh .

RUN chmod +x agent.sh

CMD ["./agent.sh"]