#!/bin/bash

# Always run from the repository root, wherever the script was started from.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Script to rebuild the frontend container
# This is needed if you see the Apache/nginx default page instead of the SSL Toolkit app

echo "🔨 Rebuilding frontend container..."
echo ""

# Stop the containers
echo "1. Stopping containers..."
docker compose down

# Rebuild the frontend
echo ""
echo "2. Building frontend (this may take several minutes)..."
docker compose build frontend --no-cache

# Start all containers
echo ""
echo "3. Starting all containers..."
docker compose up -d

# Wait for containers to start
echo ""
echo "⏳ Waiting for containers to start..."
sleep 5

# Show container status
echo ""
echo "📊 Container status:"
docker compose ps

echo ""
echo "✅ Done! Access the application at http://localhost"
echo ""
echo "To view logs:"
echo "  docker compose logs -f frontend"
echo "  docker compose logs -f backend"
echo "  docker compose logs -f nginx"
