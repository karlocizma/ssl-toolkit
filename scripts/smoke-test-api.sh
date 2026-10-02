#!/bin/bash

# Always run from the repository root, wherever the script was started from.
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# Test script for SSL Toolkit API

echo "🧪 Testing SSL Toolkit API..."

API_BASE="http://localhost/api"

# Test health endpoint
echo -e "\n📋 Testing health endpoint..."
health_response=$(curl -s "$API_BASE/health")
if echo "$health_response" | grep -q "healthy"; then
    echo "✅ Health check passed"
else
    echo "❌ Health check failed"
    echo "Response: $health_response"
fi

# Test certificate decoder with a sample certificate
echo -e "\n🔍 Testing certificate decoder..."
sample_cert='-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKZvmILy1LI9MA0GCSqGSIb3DQEBCwUAMBQxEjAQBgNVBAMMCWxv
Y2FsaG9zdDAeFw0yMzAxMDEwMDAwMDBaFw0yNDAxMDEwMDAwMDBaMBQxEjAQBgNV
BAMMCWxvY2FsaG9zdDBcMA0GCSqGSIb3DQEBAQUAA0sAMEgCQQDO1A1Q2OI9rTYv
BsXcRCh4w1q1CZR4U4RpZV7I8f8m3xpJyYF1wJ9V5i2nKx9O7g1TkWqX4+H2F6Vn
JZqL8YrAgMBAAEwDQYJKoZIhvcNAQELBQADQQC5x4FZ5i5A9+3pY8H4fB1cE8q7
2bGO8u6a0K4q3k2J4c9Y2+L4q1s1m9T5h6S2J8R3K4Fw0H8A2+Y5J2c9
-----END CERTIFICATE-----'

cert_response=$(curl -s -X POST "$API_BASE/certificate/decode" \
    -H "Content-Type: application/json" \
    -d "{\"certificate\": \"$sample_cert\"}")

if echo "$cert_response" | grep -q "success"; then
    echo "✅ Certificate decoder working"
else
    echo "❌ Certificate decoder failed"
    echo "Response: $cert_response"
fi

# Test key generation
echo -e "\n🔑 Testing key generation..."
key_response=$(curl -s -X POST "$API_BASE/key/generate" \
    -H "Content-Type: application/json" \
    -d '{"key_type": "RSA", "key_size": 2048}')

if echo "$key_response" | grep -q "success"; then
    echo "✅ Key generation working"
else
    echo "❌ Key generation failed"
    echo "Response: $key_response"
fi

# Test SSL checker
echo -e "\n🌐 Testing SSL checker..."
ssl_response=$(curl -s -X POST "$API_BASE/check/domain" \
    -H "Content-Type: application/json" \
    -d '{"hostname": "google.com", "port": 443, "timeout": 10}')

if echo "$ssl_response" | grep -q "success"; then
    echo "✅ SSL checker working"
else
    echo "⚠️  SSL checker may have issues (external dependency)"
fi

echo -e "\n🎯 API testing completed!"
echo -e "\n📋 Manual tests:"
echo "   • Open http://localhost in your browser"
echo "   • Try uploading a certificate file"
echo "   • Test the Certificate Decoder tool"
echo "   • Try generating a CSR"
echo "   • Test other SSL tools"

