FROM node:22-bookworm-slim
WORKDIR /app
COPY package.json bun.lock ./
RUN npm install --omit=dev --ignore-scripts
COPY policy.mjs transport.mjs server.mjs ./
USER node
CMD ["node", "server.mjs"]