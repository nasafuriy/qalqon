# Fixture: every line here is deliberately wrong.
FROM node:latest

ENV API_TOKEN=sk_live_notarealtoken_fixture
ARG DB_PASSWORD=hunter2fixture

RUN curl -sSL https://example.com/install.sh | sh
RUN apt-get update && apt-get install -y curl git

ADD https://example.com/payload.tar.gz /tmp/

COPY . /app
WORKDIR /app
CMD ["node", "app.js"]
