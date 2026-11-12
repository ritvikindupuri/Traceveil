# ==============================================================================
# Multi-stage Dockerfile for Traceveil
# ==============================================================================

# Stage 1: Build application assets
FROM node:22-alpine AS builder

WORKDIR /app

# Install libc compatibility for native packages if needed
RUN apk add --no-cache libc6-compat

# Copy dependency manifests
COPY package.json package-lock.json ./

# Install dependencies (including devDependencies needed for build)
RUN npm ci

# Copy project files
COPY . .

# Build production client and server bundles
RUN npm run build

# Stage 2: Minimal runtime image
FROM node:22-alpine AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=3000

# Install curl for healthcheck
RUN apk add --no-cache curl

# Create non-root system user
RUN addgroup --system --gid 1001 nodejs && \
    adduser --system --uid 1001 traceveil

# Copy dependency manifests and installed node_modules from builder
COPY package.json package-lock.json ./
COPY --from=builder /app/node_modules ./node_modules

# Copy built assets and configuration from builder
COPY --from=builder /app/dist ./dist
COPY --from=builder /app/public ./public
COPY --from=builder /app/vite.config.ts ./vite.config.ts
COPY --from=builder /app/tsconfig.json ./tsconfig.json

# Create local data directory for persistent scan storage and assign ownership
RUN mkdir -p /app/data && chown -R traceveil:nodejs /app

USER traceveil

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/ || exit 1

CMD ["npm", "run", "start"]
