# Fixture: this file must produce no findings at all.
FROM node:20.11.1-alpine3.19

RUN apk add --no-cache tini=0.19.0-r1

COPY --chown=node:node . /app
WORKDIR /app

USER node
CMD ["node", "app.js"]
