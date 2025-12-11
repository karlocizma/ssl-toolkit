# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased] - 2024-01-XX

### Added ✅

#### OCSP Certificate Revocation Checking
- Full OCSP (Online Certificate Status Protocol) implementation
- Automatic extraction of OCSP responder URLs from certificates
- Automatic issuer certificate fetching from AIA extension
- OCSP request building and response parsing
- Detailed status reporting (good, revoked, unknown)
- Revocation time and reason for revoked certificates
- Endpoint: `POST /api/check/ocsp`

#### CRL Certificate Revocation Checking
- Complete CRL (Certificate Revocation List) implementation
- CRL distribution point extraction from certificates
- CRL download and parsing (DER and PEM formats)
- Serial number verification against CRL
- Revocation date and reason extraction
- Multiple CRL URL support with fallback
- Endpoint: `POST /api/check/crl`

#### Certificate Monitoring System
- Add certificates to monitoring with labels and tags
- Track certificate expiration dates
- List all monitored certificates with status
- Get certificates expiring within N days
- Update certificate metadata (labels, tags)
- Remove certificates from monitoring
- Automatic expiration calculation
- JSON-based storage (easily upgradeable to database)
- Endpoints:
  - `POST /api/monitor/certificate/add`
  - `DELETE /api/monitor/certificate/remove/{id}`
  - `GET /api/monitor/certificate/list`
  - `GET /api/monitor/certificate/{id}`
  - `PATCH /api/monitor/certificate/{id}`
  - `GET /api/monitor/expiring`

#### Batch Certificate Processing
- Process up to 50 certificates at once
- Multiple operation support (decode, OCSP, CRL)
- Parallel processing with ThreadPoolExecutor
- Configurable worker pools
- Individual success/error tracking per item
- Endpoints:
  - `POST /api/batch/certificates/decode` (max 50 certs)
  - `POST /api/batch/domains/check` (max 20 domains)
  - `POST /api/batch/ocsp/check` (max 30 certs)
  - `POST /api/batch/crl/check` (max 20 certs)

#### Enhanced API Rate Limiting
- API key-based rate limiting system
- Per-user/per-key custom rate limits
- API key generation with custom limits
- API key validation and tracking
- Usage statistics (last used, usage count)
- API key revocation and deletion
- IP-based fallback for keyless requests
- Rate limit tracking and monitoring
- Header: `X-API-Key` for authentication
- Default limits: 200/hour, 50/minute
- Endpoints:
  - `POST /api/admin/apikey/generate`
  - `GET /api/admin/apikey/list`
  - `POST /api/admin/apikey/validate`
  - `POST /api/admin/apikey/revoke`
  - `DELETE /api/admin/apikey/delete`

### Changed

#### Backend
- Updated rate limiting configuration to support API keys
- Modified limiter key function to check for `X-API-Key` header
- Enhanced Flask app initialization with limiter context
- Improved OCSP/CRL checking from placeholder to full implementation

#### Dependencies
- Added `asn1crypto==1.5.1` for ASN.1 parsing support

### Documentation

#### New Documentation Files
- `FEATURES.md` - Comprehensive feature documentation (47+ endpoints documented)
- `QUICK_START_NEW_FEATURES.md` - Quick start guide with examples
- `CHANGELOG.md` - This changelog file
- `test_new_features.sh` - Automated testing script for new features

#### Updated Documentation
- `README.md` - Updated with new features marked with ✅
- Added new API endpoint documentation
- Updated roadmap with completed features
- Added links to detailed feature documentation

### Technical Details

#### New Backend Modules
- `app/services/cert_monitor.py` - Certificate monitoring service
- `app/services/batch_processor.py` - Batch processing service
- `app/services/api_key_manager.py` - API key management service

#### Enhanced Modules
- `app/services/ssl_checker.py` - Complete OCSP/CRL implementation
- `app/__init__.py` - Enhanced rate limiting with API key support
- `app/routes/ssl_routes.py` - Added 20+ new endpoints

#### Storage
- Certificate monitoring: `/tmp/ssl-toolkit/monitored_certificates.json`
- API keys: `/tmp/ssl-toolkit/api_keys.json`
- Note: JSON storage is suitable for development; consider database for production

### Performance

#### Batch Processing
- Concurrent certificate processing using ThreadPoolExecutor
- Configurable worker pools (max 10 for domains, 10 for OCSP, 5 for CRL)
- Timeout controls to prevent hanging requests
- Individual error handling per item

#### Rate Limiting
- Memory-based storage for development
- Per-key and per-IP tracking
- Configurable limits per API key
- Usage statistics tracking

### Security

#### API Key Security
- Secure token generation using `secrets.token_urlsafe(32)`
- API key prefix: `sslkit_` for easy identification
- Revocation capability for compromised keys
- Usage tracking for audit purposes

#### Input Validation
- Maximum batch sizes enforced (50/20/30/20)
- Worker pool limits to prevent resource exhaustion
- Timeout limits to prevent long-running requests
- Certificate format validation

### Testing

#### Test Coverage
- All Python modules compile without errors
- Automated test script provided
- Manual testing recommended for all endpoints
- Example requests in documentation

#### Test Tools
- `test_new_features.sh` - Automated API testing
- curl examples in QUICK_START_NEW_FEATURES.md
- Comprehensive API documentation in FEATURES.md

### Future Enhancements (Planned)

- Database backend for certificate/key storage (PostgreSQL/MongoDB)
- Email/Webhook alerts for expiring certificates
- Scheduled automatic certificate checks
- Real SSL Labs API integration
- Certificate templates system
- CA integration (Let's Encrypt, DigiCert, etc.)
- Enhanced dashboard UI for monitoring
- Export reports (PDF/CSV)
- Authentication system for admin endpoints

### Breaking Changes

None - All changes are backward compatible additions.

### Upgrade Notes

1. Install new dependencies: `pip install -r requirements.txt`
2. Restart the backend service
3. Optional: Generate an API key for higher rate limits
4. Optional: Review and update rate limit configuration

### Migration Notes

For production deployments:

1. **Storage Backend**: Consider migrating from JSON files to a proper database
   - Certificate monitoring → PostgreSQL table
   - API keys → PostgreSQL with encryption

2. **Rate Limiting**: Configure Redis for distributed rate limiting
   - Update `storage_uri` in Flask-Limiter configuration

3. **Security**: 
   - Secure `/api/admin/*` endpoints with authentication
   - Use HTTPS for all communications
   - Rotate API keys regularly
   - Enable logging and monitoring

4. **Monitoring**:
   - Set up cron jobs for automatic certificate checks
   - Configure alerts for expiring certificates
   - Monitor API usage statistics

### Known Issues

- JSON file storage is not suitable for high-concurrency production use
- OCSP/CRL checks require internet access
- Some certificates may not have OCSP/CRL configured
- In-memory rate limiting resets on service restart

### Acknowledgments

- Built to meet common SSL certificate management needs
- Implements industry-standard OCSP and CRL protocols
- Designed for ease of use and production deployment

---

**For detailed feature documentation, see [FEATURES.md](./FEATURES.md)**

**For quick start guide, see [QUICK_START_NEW_FEATURES.md](./QUICK_START_NEW_FEATURES.md)**
