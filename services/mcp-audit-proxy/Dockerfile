FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev --ignore-scripts
COPY policy.mjs transport.mjs server.mjs ./
USER node
# Loopback binding is intentional. Run with host networking behind a TLS gateway.
CMD ["node", "server.mjs"]