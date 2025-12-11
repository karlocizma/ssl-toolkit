# Quick Start Guide - New Features

This guide will help you quickly get started with the newly implemented features.

## Prerequisites

- Backend running on `http://localhost:5000`
- `curl` and `jq` installed (for command-line testing)

## 1. OCSP Certificate Revocation Checking

Check if a certificate has been revoked using OCSP:

```bash
# Example with a real certificate
curl -X POST http://localhost:5000/api/check/ocsp \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nYOUR_CERTIFICATE_HERE\n-----END CERTIFICATE-----"
  }'
```

**Response:**
```json
{
  "success": true,
  "result": {
    "status": "good",
    "message": "Certificate is not revoked",
    "ocsp_url": "http://ocsp.example.com",
    "checked": true
  }
}
```

## 2. CRL Certificate Revocation Checking

Check certificate against Certificate Revocation Lists:

```bash
curl -X POST http://localhost:5000/api/check/crl \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nYOUR_CERTIFICATE_HERE\n-----END CERTIFICATE-----"
  }'
```

## 3. Certificate Monitoring

### Add a Certificate to Monitoring

```bash
curl -X POST http://localhost:5000/api/monitor/certificate/add \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\nYOUR_CERT\n-----END CERTIFICATE-----",
    "label": "Production Web Server",
    "tags": ["production", "critical", "web"]
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate added to monitoring",
  "certificate_id": "cert_20240101_120000_a1b2c3d4"
}
```

### List All Monitored Certificates

```bash
curl http://localhost:5000/api/monitor/certificate/list
```

### Get Certificates Expiring Soon

```bash
# Get certificates expiring in the next 30 days
curl "http://localhost:5000/api/monitor/expiring?days=30"
```

### Remove a Certificate from Monitoring

```bash
curl -X DELETE http://localhost:5000/api/monitor/certificate/remove/cert_20240101_120000_a1b2c3d4
```

## 4. Batch Processing

### Batch Domain SSL Check

Check multiple domains at once:

```bash
curl -X POST http://localhost:5000/api/batch/domains/check \
  -H "Content-Type: application/json" \
  -d '{
    "domains": [
      {"hostname": "google.com", "port": 443, "id": "google"},
      {"hostname": "github.com", "port": 443, "id": "github"},
      {"hostname": "stackoverflow.com", "port": 443, "id": "stackoverflow"}
    ],
    "max_workers": 5,
    "timeout": 10
  }'
```

**Response:**
```json
{
  "success": true,
  "checked": 3,
  "failed": 0,
  "total": 3,
  "results": [
    {
      "id": "google",
      "hostname": "google.com",
      "success": true,
      "result": {...}
    }
  ]
}
```

### Batch Certificate Decode

Decode multiple certificates with optional OCSP/CRL checks:

```bash
curl -X POST http://localhost:5000/api/batch/certificates/decode \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": [
      "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----"
    ],
    "operations": ["decode", "ocsp"]
  }'
```

Available operations:
- `decode` - Decode certificate information
- `ocsp` - Check OCSP status
- `crl` - Check CRL status

### Batch OCSP Check

Check OCSP status for multiple certificates:

```bash
curl -X POST http://localhost:5000/api/batch/ocsp/check \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": [
      "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
      "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    ],
    "max_workers": 5
  }'
```

### Batch CRL Check

Check CRL status for multiple certificates:

```bash
curl -X POST http://localhost:5000/api/batch/crl/check \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": [
      "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
    ],
    "max_workers": 3
  }'
```

## 5. API Key Management

### Generate an API Key

```bash
curl -X POST http://localhost:5000/api/admin/apikey/generate \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "rate_limit": "1000 per hour",
    "description": "API key for production monitoring service"
  }'
```

**Response:**
```json
{
  "success": true,
  "message": "API key generated successfully",
  "api_key": "sslkit_abc123xyz789...",
  "name": "My Application",
  "rate_limit": "1000 per hour"
}
```

**⚠️ Important:** Save the API key securely. It won't be shown again!

### Use API Key in Requests

Include the API key in the `X-API-Key` header:

```bash
curl -X POST http://localhost:5000/api/check/domain \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sslkit_abc123xyz789..." \
  -d '{
    "hostname": "example.com"
  }'
```

### List API Keys

```bash
# Without showing full keys
curl http://localhost:5000/api/admin/apikey/list

# With full keys
curl "http://localhost:5000/api/admin/apikey/list?include_keys=true"
```

### Validate an API Key

```bash
curl -X POST http://localhost:5000/api/admin/apikey/validate \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sslkit_abc123xyz789..."
  }'
```

### Revoke an API Key

```bash
curl -X POST http://localhost:5000/api/admin/apikey/revoke \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sslkit_abc123xyz789..."
  }'
```

### Delete an API Key

```bash
curl -X DELETE http://localhost:5000/api/admin/apikey/delete \
  -H "Content-Type: application/json" \
  -d '{
    "api_key": "sslkit_abc123xyz789..."
  }'
```

## 6. Rate Limiting

### Default Rate Limits

- **Without API Key:** 200 requests/hour, 50 requests/minute (by IP)
- **With API Key:** Custom limits per key

### Rate Limit Headers

Check response headers for rate limit information:
- `X-RateLimit-Limit` - Total requests allowed
- `X-RateLimit-Remaining` - Requests remaining
- `X-RateLimit-Reset` - Time when limit resets

Example:
```bash
curl -I http://localhost:5000/api/health
```

## Testing the Features

Run the automated test script:

```bash
./test_new_features.sh
```

This will test all the new endpoints and provide feedback.

## Common Use Cases

### Use Case 1: Monitor Production Certificates

```bash
# 1. Add all your production certificates
curl -X POST http://localhost:5000/api/monitor/certificate/add \
  -H "Content-Type: application/json" \
  -d @prod-cert1.json

# 2. Check which ones are expiring soon
curl "http://localhost:5000/api/monitor/expiring?days=30"

# 3. Set up a cron job to check daily
# Add to crontab: 0 9 * * * curl http://localhost:5000/api/monitor/expiring?days=30 | mail -s "Expiring Certs" admin@example.com
```

### Use Case 2: Bulk Certificate Validation

```bash
# Check revocation status for all certificates at once
curl -X POST http://localhost:5000/api/batch/certificates/decode \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": ["cert1", "cert2", "cert3"],
    "operations": ["decode", "ocsp", "crl"]
  }'
```

### Use Case 3: Automated Domain Monitoring

```bash
# Check SSL for multiple domains
curl -X POST http://localhost:5000/api/batch/domains/check \
  -H "Content-Type: application/json" \
  -H "X-API-Key: YOUR_API_KEY" \
  -d '{
    "domains": [
      {"hostname": "example.com"},
      {"hostname": "example.org"},
      {"hostname": "example.net"}
    ]
  }'
```

## Troubleshooting

### OCSP/CRL Checks Failing

- Ensure your server has internet access
- Some certificates don't have OCSP/CRL configured
- Check certificate for OCSP/CRL URLs in the AIA extension

### Rate Limit Exceeded

- Generate an API key with higher limits
- Include the API key in your requests with `X-API-Key` header

### Certificate Not Added to Monitoring

- Ensure certificate is in valid PEM format
- Check if certificate is already being monitored (duplicate serial numbers)

## Next Steps

1. Read the full [FEATURES.md](./FEATURES.md) documentation
2. Check the main [README.md](./README.md) for general usage
3. Explore the API with tools like Postman or Insomnia
4. Integrate the API into your monitoring systems

## Support

For issues or questions:
- Check the [FEATURES.md](./FEATURES.md) documentation
- Review API responses for error messages
- Open an issue on the project repository

---

**Happy certificate monitoring! 🔐**
