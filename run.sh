#!/bin/bash

# SSL Toolkit Run Script

set -e

echo "🚀 Starting SSL Certificate Toolkit..."

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available (try both docker-compose and docker compose)
DOCKER_COMPOSE="docker compose"
if ! docker compose version &> /dev/null; then
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE="docker-compose"
    else
        echo "❌ Docker Compose is not available. Please install Docker Compose and try again."
        exit 1
    fi
fi

echo "Using: $DOCKER_COMPOSE"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs

# Build and start the containers
echo "🐳 Building and starting Docker containers..."
echo "   This may take several minutes on first run..."
$DOCKER_COMPOSE up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 15

# Check if services are running
echo "🔍 Checking service health..."
echo ""

# Check backend
if curl -f http://localhost/api/health &> /dev/null; then
    echo "✅ Backend service is healthy"
else
    echo "⚠️  Backend service may not be ready yet"
    echo "   Run: $DOCKER_COMPOSE logs backend"
fi

# Check frontend
if curl -f http://localhost &> /dev/null; then
    RESPONSE=$(curl -s http://localhost)
    if echo "$RESPONSE" | grep -q "SSL Certificate Toolkit\|root"; then
        echo "✅ Frontend service is healthy"
    else
        echo "⚠️  Frontend is running but may not be built correctly"
        echo "   If you see a default page, run: ./rebuild-frontend.sh"
    fi
else
    echo "⚠️  Frontend service may not be ready yet"
    echo "   Run: $DOCKER_COMPOSE logs frontend"
fi

# Check nginx
if $DOCKER_COMPOSE ps nginx | grep -q "Up"; then
    echo "✅ Nginx proxy is running"
else
    echo "⚠️  Nginx proxy may not be running"
    echo "   Run: $DOCKER_COMPOSE logs nginx"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🎉 SSL Certificate Toolkit is starting up!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "📍 Application: http://localhost"
echo "📍 API Health:  http://localhost/api/health"
echo "📍 Backend:     http://localhost:5000 (internal)"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "📋 Useful Commands:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  View logs:        $DOCKER_COMPOSE logs -f"
echo "  View backend:     $DOCKER_COMPOSE logs -f backend"
echo "  View frontend:    $DOCKER_COMPOSE logs -f frontend"
echo "  Stop:             $DOCKER_COMPOSE down"
echo "  Restart:          $DOCKER_COMPOSE restart"
echo "  Rebuild frontend: ./rebuild-frontend.sh"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "🔧 Available Tools:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  • Certificate Decoder & Fingerprint Generator"
echo "  • CSR Generator & Decoder"
echo "  • SSL/TLS Checker for Domains"
echo "  • Certificate Format Converter (PFX, PEM, DER)"
echo "  • Private Key Generator & Validator"
echo "  • Key-Certificate Matcher"
echo "  • Certificate Chain Checker"
echo "  • DMARC & SPF Manager"
echo "  • Email Header Analyzer"
echo "  • Password Toolkit"
echo "  • DNS Diagnostics"
echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "💡 Tips:"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  • If you see a default page: ./rebuild-frontend.sh"
echo "  • HTTPS is disabled by default (dev mode)"
echo "  • For troubleshooting: See TROUBLESHOOTING.md"
echo ""
echo "Happy SSL certificate management! 🔐"

