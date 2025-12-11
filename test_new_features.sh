#!/bin/bash

# Test script for new features
# This script tests the newly implemented features

echo "=========================================="
echo "Testing New SSL Toolkit Features"
echo "=========================================="
echo ""

API_BASE="http://localhost:5000/api"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test health check first
echo -e "${YELLOW}1. Testing Health Check${NC}"
curl -s "${API_BASE}/health" | jq '.' || echo "Health check failed"
echo ""

# Test API Key Generation
echo -e "${YELLOW}2. Testing API Key Generation${NC}"
API_KEY_RESPONSE=$(curl -s -X POST "${API_BASE}/admin/apikey/generate" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test Application",
    "rate_limit": "500 per hour",
    "description": "Testing API key functionality"
  }')

echo "$API_KEY_RESPONSE" | jq '.'
API_KEY=$(echo "$API_KEY_RESPONSE" | jq -r '.api_key // empty')
echo ""

# Test List API Keys
echo -e "${YELLOW}3. Testing List API Keys${NC}"
curl -s "${API_BASE}/admin/apikey/list" | jq '.'
echo ""

# Test Certificate Monitoring
echo -e "${YELLOW}4. Testing Certificate Monitoring (List - should be empty initially)${NC}"
curl -s "${API_BASE}/monitor/certificate/list" | jq '.'
echo ""

# Test Batch Domain Check
echo -e "${YELLOW}5. Testing Batch Domain SSL Check${NC}"
curl -s -X POST "${API_BASE}/batch/domains/check" \
  -H "Content-Type: application/json" \
  -d '{
    "domains": [
      {"hostname": "google.com", "port": 443, "id": "google"},
      {"hostname": "github.com", "port": 443, "id": "github"}
    ],
    "max_workers": 2,
    "timeout": 10
  }' | jq '.'
echo ""

# Test with API Key header
if [ ! -z "$API_KEY" ]; then
  echo -e "${YELLOW}6. Testing Request with API Key${NC}"
  curl -s -X POST "${API_BASE}/check/domain" \
    -H "Content-Type: application/json" \
    -H "X-API-Key: $API_KEY" \
    -d '{
      "hostname": "google.com",
      "port": 443
    }' | jq '.success, .result.hostname, .result.connection_secure'
  echo ""
fi

# Test Expiring Certificates
echo -e "${YELLOW}7. Testing Get Expiring Certificates${NC}"
curl -s "${API_BASE}/monitor/expiring?days=30" | jq '.'
echo ""

echo -e "${GREEN}=========================================="
echo "Feature Tests Complete!"
echo "==========================================${NC}"
echo ""
echo "Note: Some tests may fail if the backend is not running."
echo "Start the backend with: cd backend && python app.py"
echo ""
echo "For detailed feature documentation, see: FEATURES.md"
