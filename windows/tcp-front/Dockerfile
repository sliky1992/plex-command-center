# PCC TCP-Front sidecar
#
# Standalone container that runs only the TCP pass-through geofence proxy.
# Reads PCC's pcc.db from a shared volume; logs decisions back into gateway_log.
#
# Must run with `network_mode: host` so:
#   - it can listen on the host's :32401 directly (port publishing would NAT and
#     break the source-IP geofence check)
#   - it can reach Plex Media Server on 127.0.0.1:32400 (host loopback)
#
# Linux only (network_mode: host doesn't work on Docker Desktop for Win/Mac).

FROM node:20-bullseye-slim

WORKDIR /app

# Install deps first so this layer caches across index.js edits.
COPY package.json ./
RUN npm install --omit=optional --omit=dev --no-audit --no-fund \
 && rm -rf /root/.npm

COPY index.js ./

# Sensible defaults for the docker-compose case.
ENV TCP_PORT=32401 \
    PMS_HOST=127.0.0.1 \
    PMS_PORT=32400 \
    PCC_DB_PATH=/pcc-data/pcc.db

CMD ["node", "index.js"]
