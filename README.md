# SSL Certificate Toolkit

A comprehensive web-based SSL/TLS certificate management toolkit built with Flask (Python) backend and React frontend, running in Docker containers.

## Features

### Core SSL Tools
- **Certificate Decoder** - Decode and analyze SSL/TLS certificates
- **CSR Generator** - Generate Certificate Signing Requests with private keys
- **CSR Decoder** - Decode and analyze Certificate Signing Requests
- **SSL Checker** - Check SSL certificates for domains and URLs
- **Certificate Converter** - Convert between certificate formats (PFX ↔ PEM, DER ↔ PEM)
- **Key Generator** - Generate RSA and EC private keys
- **Key Validator** - Validate and analyze private keys
- **Key-Certificate Match** - Verify if private key matches certificate
- **Certificate Chain Checker** - Analyze and validate certificate chains

### Advanced Features
- **Certificate Fingerprint Generator** - Generate SHA-1, SHA-256 fingerprints
- **Subject Alternative Names (SAN) Extractor** - Extract and display SANs
- **Certificate Expiration Monitor** - Check certificate expiration dates
- **OCSP/CRL Checker** - Verify certificate revocation status (planned)
- **SSL Labs API Integration** - Get SSL ratings for domains (planned)

## Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│                 │    │                 │    │                 │
│  React Frontend │◄──►│  Nginx Proxy    │◄──►│  Flask Backend  │
│   (Port 3000)   │    │   (Port 80/443) │    │   (Port 5000)   │
│                 │    │                 │    │                 │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## Technology Stack

### Backend
- **Flask** - Python web framework
- **cryptography** - Python cryptographic library
- **pyOpenSSL** - OpenSSL bindings for Python
- **Gunicorn** - WSGI HTTP Server
- **Flask-CORS** - Cross-Origin Resource Sharing
- **Flask-Limiter** - Rate limiting

### Frontend
- **React 18** - Frontend framework
- **Material-UI** - React component library
- **Axios** - HTTP client
- **React Router** - Client-side routing
- **React Dropzone** - File upload component

### Infrastructure
- **Docker** - Containerization
- **Docker Compose** - Multi-container orchestration
- **Nginx** - Reverse proxy and static file serving
- **Alpine Linux** - Lightweight container base images

## Quick Start

### Prerequisites
- Docker and Docker Compose
- Git

### Installation

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd ssl-toolkit
   ```

2. **Build and run with Docker Compose**
   ```bash
   docker-compose up --build
   ```

   This command builds all containers and starts the application. The initial build may take several minutes.

3. **Access the application**
   - Open your browser and navigate to `http://localhost`
   - The application will be available on port 80
   - The backend API will be available at `http://localhost/api`

**Note**: If you see a default web server page instead of the application:
- Quick fix: Run `./rebuild-frontend.sh` (provided in the repository)
- Or manually: `docker compose build frontend --no-cache && docker compose up -d`
- See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for detailed solutions

### Development Mode

For development with hot reloading:

1. **Backend Development**
   ```bash
   cd backend
   pip install -r requirements.txt
   python app.py
   ```

2. **Frontend Development**
   ```bash
   cd frontend
   npm install
   npm start
   ```

## Configuration

### Environment Variables

Create a `.env` file in the root directory:

```env
SECRET_KEY=your-secret-key-change-in-production
FLASK_ENV=production
REACT_APP_API_URL=/api
```

### SSL/HTTPS Configuration

**Note:** HTTPS is disabled by default for development. The application runs on HTTP (port 80) out of the box.

For HTTPS support in production:

1. **Generate SSL certificates**
   ```bash
   mkdir -p certs
   openssl req -x509 -newkey rsa:4096 -keyout certs/key.pem -out certs/cert.pem -days 365 -nodes
   ```

2. **Generate DH parameters**
   ```bash
   openssl dhparam -out certs/dhparam.pem 2048
   ```

3. **Update nginx configuration**
   - Edit `nginx/nginx.conf`
   - Uncomment the HTTPS server block (lines 50-92)
   - Restart containers: `docker-compose restart nginx`

## Troubleshooting

Having issues? See the comprehensive [TROUBLESHOOTING.md](TROUBLESHOOTING.md) guide for detailed solutions.

### Quick Fixes

**Frontend shows default page?**
```bash
./rebuild-frontend.sh
```

**Backend won't start?**
```bash
docker compose build backend --no-cache
docker compose up -d
```

**View logs:**
```bash
docker compose logs -f
```

For detailed troubleshooting of all common issues, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## API Documentation

### Certificate Operations

#### Decode Certificate
```http
POST /api/certificate/decode
Content-Type: application/json

{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

#### Get Certificate Fingerprints
```http
POST /api/certificate/fingerprint
Content-Type: application/json

{
  "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
}
```

### CSR Operations

#### Generate CSR
```http
POST /api/csr/generate
Content-Type: application/json

{
  "subject": {
    "common_name": "example.com",
    "country": "US",
    "organization": "Example Corp"
  },
  "key_type": "RSA",
  "key_size": 2048,
  "subject_alternative_names": ["www.example.com", "api.example.com"]
}
```

#### Decode CSR
```http
POST /api/csr/decode
Content-Type: application/json

{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...\n-----END CERTIFICATE REQUEST-----"
}
```

### Key Operations

#### Generate Private Key
```http
POST /api/key/generate
Content-Type: application/json

{
  "key_type": "RSA",
  "key_size": 2048
}
```

#### Validate Private Key
```http
POST /api/key/validate
Content-Type: application/json

{
  "private_key": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
  "password": "optional-password"
}
```

### SSL Checking

#### Check Domain SSL
```http
POST /api/check/domain
Content-Type: application/json

{
  "hostname": "example.com",
  "port": 443,
  "timeout": 10
}
```

### Certificate Conversion

#### Convert Certificate Format
```http
POST /api/convert
Content-Type: application/json

{
  "certificate_data": "...",
  "input_format": "PFX",
  "output_format": "PEM",
  "password": "optional-pfx-password"
}
```

## Security Features

- **Input Validation** - Strict validation of all uploaded files and data
- **Rate Limiting** - Protection against abuse and DoS attacks
- **Secure Headers** - Security headers for XSS, CSRF protection
- **HTTPS Support** - SSL/TLS encryption for all communications
- **File Sanitization** - Secure handling of uploaded certificate files
- **Temporary File Cleanup** - Automatic cleanup of temporary files
- **Non-root Containers** - Containers run with non-privileged users

## File Upload Support

Supported certificate file formats:
- `.pem` - PEM encoded certificates
- `.crt` - Certificate files
- `.cer` - Certificate files
- `.pfx` - PKCS#12 files
- `.p12` - PKCS#12 files
- `.der` - DER encoded certificates

## Browser Support

- Chrome/Chromium 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
- Create an issue on GitHub
- Check the documentation
- Review the API documentation

## Roadmap

### Planned Features
- [ ] SSL Labs API integration
- [ ] OCSP/CRL checking implementation
- [ ] Certificate monitoring and alerts
- [ ] Batch certificate processing
- [ ] Certificate template system
- [ ] REST API rate limiting per user
- [ ] Certificate storage and management
- [ ] Integration with popular CAs
- [ ] Mobile app support
- [ ] Advanced certificate analytics

## Performance

- **Backend**: Handles 100+ concurrent requests
- **Frontend**: Optimized React build with code splitting
- **Caching**: Nginx static file caching
- **Compression**: Gzip compression enabled
- **Health Checks**: Container health monitoring

## Deployment

### Production Deployment

1. **Set production environment variables**
2. **Configure SSL certificates**
3. **Set up monitoring and logging**
4. **Configure firewall rules**
5. **Set up backup procedures**

### Docker Hub

Images are available on Docker Hub:
- `ssl-toolkit/backend`
- `ssl-toolkit/frontend`

### Kubernetes

Kubernetes manifests are available in the `k8s/` directory (planned).

---

**Built with ❤️ for the SSL/TLS community**

