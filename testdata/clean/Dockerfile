# Fixture: this file must produce no findings at all.
FROM node:20.11.1-alpine3.19

RUN apk add --no-cache tini=0.19.0-r1

# Regression guard for docker-curl-pipe-shell: a verified download on one RUN
# line and an unrelated pipe on another must not be read as "curl | sh".
RUN curl -fsSLo /tmp/tool.tgz https://example.com/tool.tgz \
 && sha256sum -c /tmp/tool.sha256
RUN tar -tzf /tmp/tool.tgz | head -1

COPY --chown=node:node . /app
WORKDIR /app

USER node
CMD ["node", "app.js"]
