# Fixture: every line here is deliberately wrong.
FROM alpine AS builder

FROM node:latest

ENV API_TOKEN=sk_live_notarealtoken_fixture
ARG DB_PASSWORD=hunter2fixture

RUN curl -sSL https://example.com/install.sh | sh
RUN apt-get update && apt-get install -y curl git
RUN pip install requests

ADD https://example.com/payload.tar.gz /tmp/
COPY id_rsa /root/.ssh/id_rsa

COPY . /app
WORKDIR /app
RUN chmod -R 777 /app
CMD ["node", "app.js"]
