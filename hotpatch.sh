#!/bin/bash
# Hotpatch - copies backend + frontend into the running container. No full rebuild needed.

set -e
cd "$(dirname "$0")"

CONTAINER=$(docker ps --filter name=plex-command-center --format "{{.Names}}" | head -1)

if [ -z "$CONTAINER" ]; then
  echo "No running plex-command-center container found."
  echo "Starting via docker-compose..."
  docker-compose up -d
  exit 0
fi

echo "Container: $CONTAINER"
echo "Copying backend..."
docker cp backend-server.js "$CONTAINER":/app/backend-server.js

echo "Copying frontend..."
docker cp plex-command-center-v2.5.2-final.html "$CONTAINER":/app/public/index.html

echo "Restarting..."
docker restart "$CONTAINER"

sleep 3
echo "Done."
docker logs "$CONTAINER" --tail 10
