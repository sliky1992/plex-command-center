FROM node:18-alpine

WORKDIR /app

# Install build dependencies for native modules
RUN apk add --no-cache python3 make g++ linux-headers

# Copy package file and install dependencies
COPY package.json ./
RUN npm install --production

# Create required directories
RUN mkdir -p /app/data /app/logs /app/public

# Copy application files
COPY backend-server.js ./
COPY index.html ./public/

EXPOSE 3001

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3001/api/health',(r)=>{process.exit(r.statusCode===200?0:1)})"

CMD ["node", "backend-server.js"]
