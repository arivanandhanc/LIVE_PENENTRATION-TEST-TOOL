# PenTestTool — minimal production image.
FROM node:20-alpine

WORKDIR /app

# Install only production deps for a small, reproducible image.
COPY package.json package-lock.json ./
RUN npm ci --omit=dev

# App source.
COPY . .

# Persisted scan data.
RUN mkdir -p /app/data
VOLUME ["/app/data"]

ENV PORT=3000 \
    HOST=0.0.0.0 \
    ALLOW_PRIVATE=false

EXPOSE 3000

# Drop to the non-root user shipped with the node image.
USER node

CMD ["node", "server.js"]
