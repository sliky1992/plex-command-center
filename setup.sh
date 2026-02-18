#!/bin/bash
set -e

echo "╔══════════════════════════════════════════════════════╗"
echo "║  🎬 Plex Command Center v2.5.2 - Quick Setup        ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "❌ Docker is not installed. Please install Docker first."
    echo "   Visit: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose first."
    echo "   Visit: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "✅ Docker found: $(docker --version)"
echo "✅ Docker Compose found: $(docker-compose --version)"
echo ""

# Check if docker-compose.yml exists
if [ -f "docker-compose.yml" ]; then
    echo "⚠️  docker-compose.yml already exists."
    read -p "   Overwrite? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "❌ Setup cancelled."
        exit 1
    fi
fi

# Copy example config
echo "📋 Creating docker-compose.yml from example..."
cp docker-compose.yml.example docker-compose.yml

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  ⚙️  Configuration Required                          ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "You need to configure your API keys and URLs."
echo "Opening docker-compose.yml in nano..."
echo ""
echo "Please set:"
echo "  1. PLEX_URL and PLEX_TOKEN"
echo "  2. TAUTULLI_URL and TAUTULLI_API_KEY"
echo "  3. JELLYSEERR_URL and JELLYSEERR_API_KEY"
echo "  4. (Optional) ZABBIX_* variables for server metrics"
echo ""
read -p "Press Enter to open editor..."

nano docker-compose.yml

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║  🚀 Building and Starting                            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Build
echo "🔨 Building Docker image..."
docker-compose build

# Start
echo "▶️  Starting container..."
docker-compose up -d

# Wait a moment
sleep 3

# Check if running
if docker ps | grep -q plex-command-center; then
    echo ""
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║  ✅ SUCCESS!                                         ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo ""
    echo "🌐 Dashboard is running at:"
    echo "   http://localhost:3001"
    echo ""
    echo "📋 Useful commands:"
    echo "   docker-compose logs -f     # View logs"
    echo "   docker-compose restart     # Restart"
    echo "   docker-compose down        # Stop"
    echo ""
else
    echo ""
    echo "❌ Container failed to start. Check logs:"
    echo "   docker-compose logs"
fi
