# New Features Documentation

This document describes the newly implemented features for the SSL Certificate Toolkit.

## Features Implemented

### 1. OCSP (Online Certificate Status Protocol) Checking ✅

Full implementation of OCSP certificate revocation checking.

**Endpoint:** `POST /api/check/ocsp`

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "status": "good|revoked|unknown|unavailable|error",
    "message": "Certificate is not revoked",
    "ocsp_url": "http://ocsp.example.com",
    "checked": true,
    "produced_at": "2024-01-01T00:00:00",
    "this_update": "2024-01-01T00:00:00",
    "next_update": "2024-01-08T00:00:00"
  }
}
```

**Features:**
- Extracts OCSP responder URL from certificate
- Automatically fetches issuer certificate for OCSP request
- Makes OCSP request and validates response
- Returns detailed status information including revocation time and reason if revoked

---

### 2. CRL (Certificate Revocation List) Checking ✅

Implementation of CRL-based certificate revocation checking.

**Endpoint:** `POST /api/check/crl`

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

**Response:**
```json
{
  "success": true,
  "result": {
    "status": "good|revoked|unavailable|error",
    "message": "Certificate is not in the revocation list",
    "crl_url": "http://crl.example.com/crl.der",
    "checked": true,
    "last_update": "2024-01-01T00:00:00",
    "next_update": "2024-01-08T00:00:00"
  }
}
```

**Features:**
- Extracts CRL distribution points from certificate
- Downloads and parses CRL files (DER and PEM formats)
- Checks certificate serial number against CRL
- Returns revocation date and reason if found

---

### 3. Certificate Monitoring and Alerts ✅

Track certificates and get alerts for expiring certificates.

#### Add Certificate to Monitoring
**Endpoint:** `POST /api/monitor/certificate/add`

**Request:**
```json
{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
  "label": "Production Web Server",
  "tags": ["production", "web", "critical"]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Certificate added to monitoring",
  "certificate_id": "cert_20240101_120000_a1b2c3d4",
  "certificate": {
    "id": "cert_20240101_120000_a1b2c3d4",
    "label": "Production Web Server",
    "common_name": "example.com",
    "not_before": "2024-01-01T00:00:00",
    "not_after": "2025-01-01T00:00:00",
    "tags": ["production", "web", "critical"]
  }
}
```

#### List Monitored Certificates
**Endpoint:** `GET /api/monitor/certificate/list?include_pem=false`

**Response:**
```json
{
  "success": true,
  "count": 5,
  "certificates": [
    {
      "id": "cert_20240101_120000_a1b2c3d4",
      "label": "Production Web Server",
      "common_name": "example.com",
      "days_until_expiry": 45,
      "is_expired": false,
      "expires_soon": false,
      "tags": ["production"]
    }
  ]
}
```

#### Get Expiring Certificates
**Endpoint:** `GET /api/monitor/expiring?days=30`

**Response:**
```json
{
  "success": true,
  "count": 2,
  "days_threshold": 30,
  "certificates": [
    {
      "id": "cert_20240101_120000_a1b2c3d4",
      "label": "Production Web Server",
      "days_until_expiry": 15,
      "common_name": "example.com"
    }
  ]
}
```

#### Update Certificate Metadata
**Endpoint:** `PATCH /api/monitor/certificate/{certificate_id}`

#### Remove Certificate from Monitoring
**Endpoint:** `DELETE /api/monitor/certificate/remove/{certificate_id}`

---

### 4. Batch Certificate Processing ✅

Process multiple certificates or domains in a single request.

#### Batch Decode Certificates
**Endpoint:** `POST /api/batch/certificates/decode`

**Request:**
```json
{
  "certificates": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ],
  "operations": ["decode", "ocsp", "crl"]
}
```

**Response:**
```json
{
  "success": true,
  "processed": 2,
  "failed": 0,
  "total": 2,
  "results": [
    {
      "id": "cert_1",
      "index": 0,
      "success": true,
      "certificate_info": {...},
      "ocsp_status": {...},
      "crl_status": {...}
    }
  ],
  "errors": []
}
```

**Limits:**
- Maximum 50 certificates per batch
- Operations: `decode`, `ocsp`, `crl`

#### Batch Domain SSL Check
**Endpoint:** `POST /api/batch/domains/check`

**Request:**
```json
{
  "domains": [
    {"hostname": "example.com", "port": 443, "id": "server1"},
    {"hostname": "example.org", "port": 443, "id": "server2"}
  ],
  "max_workers": 5,
  "timeout": 10
}
```

**Response:**
```json
{
  "success": true,
  "checked": 2,
  "failed": 0,
  "total": 2,
  "results": [
    {
      "id": "server1",
      "hostname": "example.com",
      "port": 443,
      "success": true,
      "result": {...}
    }
  ],
  "errors": []
}
```

**Limits:**
- Maximum 20 domains per batch
- Concurrent checks with configurable workers (max 10)
- Configurable timeout (max 30 seconds)

#### Batch OCSP Check
**Endpoint:** `POST /api/batch/ocsp/check`

**Request:**
```json
{
  "certificates": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ],
  "max_workers": 5
}
```

**Limits:**
- Maximum 30 certificates per batch
- Parallel processing with configurable workers

#### Batch CRL Check
**Endpoint:** `POST /api/batch/crl/check`

**Request:**
```json
{
  "certificates": [
    "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  ],
  "max_workers": 3
}
```

**Limits:**
- Maximum 20 certificates per batch
- Parallel processing (max 5 workers due to CRL download size)

---

### 5. Enhanced API Rate Limiting ✅

API key-based rate limiting with per-user limits.

#### Default Rate Limits
- **Without API Key:** 200 requests/hour, 50 requests/minute (by IP address)
- **With API Key:** Custom limits per key

#### Using API Keys

Include the API key in the request header:
```
X-API-Key: sslkit_your_api_key_here
```

#### Generate API Key
**Endpoint:** `POST /api/admin/apikey/generate`

**Request:**
```json
{
  "name": "My Application",
  "rate_limit": "500 per hour",
  "description": "API key for production monitoring"
}
```

**Response:**
```json
{
  "success": true,
  "message": "API key generated successfully",
  "api_key": "sslkit_abc123...",
  "name": "My Application",
  "rate_limit": "500 per hour"
}
```

#### List API Keys
**Endpoint:** `GET /api/admin/apikey/list?include_keys=false`

**Response:**
```json
{
  "success": true,
  "count": 3,
  "keys": [
    {
      "name": "My Application",
      "rate_limit": "500 per hour",
      "created_at": "2024-01-01T00:00:00",
      "last_used": "2024-01-01T12:00:00",
      "usage_count": 150,
      "active": true,
      "key_preview": "sslkit_abc123..."
    }
  ]
}
```

#### Validate API Key
**Endpoint:** `POST /api/admin/apikey/validate`

#### Revoke API Key
**Endpoint:** `POST /api/admin/apikey/revoke`

#### Delete API Key
**Endpoint:** `DELETE /api/admin/apikey/delete`

---

## Usage Examples

### Example 1: Check Certificate Revocation Status

```bash
# Check OCSP status
curl -X POST http://localhost:5000/api/check/ocsp \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'

# Check CRL status
curl -X POST http://localhost:5000/api/check/crl \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
  }'
```

### Example 2: Monitor Certificates

```bash
# Add certificate to monitoring
curl -X POST http://localhost:5000/api/monitor/certificate/add \
  -H "Content-Type: application/json" \
  -d '{
    "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "label": "Production Server",
    "tags": ["production", "critical"]
  }'

# Get expiring certificates
curl -X GET "http://localhost:5000/api/monitor/expiring?days=30"

# List all monitored certificates
curl -X GET "http://localhost:5000/api/monitor/certificate/list"
```

### Example 3: Batch Processing

```bash
# Check multiple domains
curl -X POST http://localhost:5000/api/batch/domains/check \
  -H "Content-Type: application/json" \
  -d '{
    "domains": [
      {"hostname": "google.com", "port": 443},
      {"hostname": "github.com", "port": 443},
      {"hostname": "stackoverflow.com", "port": 443}
    ],
    "max_workers": 5,
    "timeout": 10
  }'

# Batch decode and check certificates
curl -X POST http://localhost:5000/api/batch/certificates/decode \
  -H "Content-Type: application/json" \
  -d '{
    "certificates": ["cert1_pem", "cert2_pem"],
    "operations": ["decode", "ocsp"]
  }'
```

### Example 4: Use API Key

```bash
# Generate API key
curl -X POST http://localhost:5000/api/admin/apikey/generate \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My App",
    "rate_limit": "1000 per hour"
  }'

# Use API key in requests
curl -X POST http://localhost:5000/api/check/domain \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sslkit_your_key_here" \
  -d '{
    "hostname": "example.com"
  }'
```

---

## Benefits of New Features

### OCSP/CRL Checking
- **Real-time revocation checking** - Verify certificates haven't been revoked
- **Compliance** - Meet security standards requiring revocation checks
- **Trust validation** - Ensure certificates are still trustworthy

### Certificate Monitoring
- **Proactive management** - Track certificate expiration dates
- **Prevent outages** - Get alerts before certificates expire
- **Organized tracking** - Tag and label certificates for easy management
- **Bulk oversight** - Monitor multiple certificates from one dashboard

### Batch Processing
- **Efficiency** - Process multiple certificates/domains at once
- **Time savings** - Reduce API calls and processing time
- **Parallel processing** - Concurrent checks for faster results
- **Bulk operations** - Ideal for managing large certificate portfolios

### Enhanced Rate Limiting
- **Fair usage** - Prevent API abuse
- **Custom limits** - Different limits for different users
- **API key tracking** - Monitor usage and last access
- **Flexibility** - Configurable rate limits per key

---

## Technical Details

### Dependencies Added
- `asn1crypto==1.5.1` - For ASN.1 parsing support

### Storage
- Certificate monitoring data: `/tmp/ssl-toolkit/monitored_certificates.json`
- API keys data: `/tmp/ssl-toolkit/api_keys.json`
- In production, consider using a proper database (PostgreSQL, MongoDB, etc.)

### Rate Limiting
- Uses Flask-Limiter with memory storage
- Key function checks for `X-API-Key` header
- Falls back to IP-based limiting if no API key provided

### Concurrency
- Batch operations use ThreadPoolExecutor
- Configurable worker pools for parallel processing
- Timeouts to prevent hanging requests

---

## Future Enhancements

### Potential Improvements
1. **Database backend** - Replace JSON files with proper database
2. **Email/Webhook alerts** - Send notifications for expiring certificates
3. **SSL Labs integration** - Add real SSL Labs API integration
4. **Certificate templates** - Pre-configured certificate request templates
5. **CA integration** - Direct integration with Let's Encrypt, DigiCert, etc.
6. **Dashboard UI** - Enhanced frontend for monitoring and management
7. **Scheduled checks** - Automatic periodic certificate validation
8. **Export reports** - Generate PDF/CSV reports of certificate status

---

## Security Considerations

1. **API Keys** - Store securely, rotate regularly
2. **Rate Limiting** - Adjust limits based on your infrastructure
3. **OCSP/CRL** - Network requests to external services (consider caching)
4. **Input Validation** - All inputs are validated before processing
5. **File Storage** - Consider encryption for stored certificates
6. **Admin Endpoints** - Secure `/admin/*` endpoints with authentication

---

## Testing

Test the new features:

```bash
# Run the backend
cd backend
python app.py

# Test OCSP checking
curl -X POST http://localhost:5000/api/check/ocsp \
  -H "Content-Type: application/json" \
  -d '{"certificate": "YOUR_CERT_HERE"}'

# Test monitoring
curl -X GET http://localhost:5000/api/monitor/certificate/list

# Test batch processing
curl -X POST http://localhost:5000/api/batch/domains/check \
  -H "Content-Type: application/json" \
  -d '{"domains": [{"hostname": "google.com"}]}'
```

---

## Support

For issues or questions about these features, please open an issue on the project repository.
