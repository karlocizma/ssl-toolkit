#!/bin/bash

# SSL Toolkit Run Script

set -e

echo "🚀 Starting SSL Certificate Toolkit..."

# Check if Docker is running
if ! docker info &> /dev/null; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Check if Docker Compose is available
if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose is not installed. Please install Docker Compose and try again."
    exit 1
fi

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p certs logs

# Generate self-signed certificate if it doesn't exist
if [ ! -f "certs/cert.pem" ] || [ ! -f "certs/key.pem" ]; then
    echo "🔐 Generating self-signed SSL certificate..."
    openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem \
        -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" 2>/dev/null
    echo "✅ SSL certificate generated"
fi

# Generate DH parameters if they don't exist
if [ ! -f "certs/dhparam.pem" ]; then
    echo "🔒 Generating DH parameters (this may take a while)..."
    openssl dhparam -out certs/dhparam.pem 2048 2>/dev/null
    echo "✅ DH parameters generated"
fi

# Build and start the containers
echo "🐳 Building and starting Docker containers..."
docker-compose up --build -d

# Wait for services to be ready
echo "⏳ Waiting for services to be ready..."
sleep 10

# Check if services are running
echo "🔍 Checking service health..."
if curl -f http://localhost/api/health &> /dev/null; then
    echo "✅ Backend service is healthy"
else
    echo "⚠️  Backend service may not be ready yet"
fi

if curl -f http://localhost &> /dev/null; then
    echo "✅ Frontend service is healthy"
else
    echo "⚠️  Frontend service may not be ready yet"
fi

echo ""
echo "🎉 SSL Certificate Toolkit is starting up!"
echo "📍 Application URL: http://localhost"
echo "📍 API Health Check: http://localhost/api/health"
echo ""
echo "📋 To view logs: docker-compose logs -f"
echo "⏹️  To stop: docker-compose down"
echo "🔄 To restart: docker-compose restart"
echo ""
echo "🔧 Available tools:"
echo "   • Certificate Decoder"
echo "   • CSR Generator & Decoder"
echo "   • SSL Checker"
echo "   • Certificate Converter"
echo "   • Key Generator & Validator"
echo "   • Key-Certificate Matcher"
echo "   • Certificate Chain Checker"
echo ""
echo "Happy SSL certificate management! 🔐"

