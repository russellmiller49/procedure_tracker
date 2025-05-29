# Multi-stage Dockerfile for Node.js application
FROM node:18-alpine AS base

# Install necessary packages
RUN apk add --no-cache \
    openssl \
    curl \
    bash \
    ca-certificates \
    && update-ca-certificates

# Create app directory
WORKDIR /app

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

# Stage 1: Dependencies
FROM base AS dependencies

# Copy package files
COPY package*.json ./

# Install production dependencies
RUN npm ci --only=production && \
    npm cache clean --force

# Copy production dependencies
RUN cp -R node_modules prod_node_modules

# Install all dependencies (including dev)
RUN npm ci && \
    npm cache clean --force

# Stage 2: Build
FROM dependencies AS build

# Copy source code
COPY . .

# Run tests
RUN npm run test

# Build application (if needed)
RUN npm run build || true

# Stage 3: Production
FROM base AS production

# Set NODE_ENV
ENV NODE_ENV=production

# Copy production dependencies
COPY --from=dependencies /app/prod_node_modules ./node_modules

# Copy built application
COPY --from=build /app/dist ./dist
COPY --from=build /app/public ./public
COPY --from=build /app/server.js ./
COPY --from=build /app/config ./config
COPY --from=build /app/models ./models
COPY --from=build /app/routes ./routes
COPY --from=build /app/middleware ./middleware
COPY --from=build /app/utils ./utils
COPY --from=build /app/services ./services

# Create necessary directories
RUN mkdir -p logs uploads temp && \
    chown -R nodejs:nodejs /app

# Security hardening
RUN chmod -R 750 /app && \
    chmod -R 770 /app/logs /app/uploads /app/temp

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD node healthcheck.js || exit 1

# Start command
CMD ["node", "server.js"]
