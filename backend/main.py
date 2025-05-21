# backend/main.py

from fastapi import FastAPI, UploadFile, File, Form
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import base64
import ssl
import socket
import subprocess
import tempfile
import os

app = FastAPI()

# ----- Models -----
class CSRDecodeRequest(BaseModel):
    csr: str

class SSLDecodeRequest(BaseModel):
    certificate: str

class SSLCheckRequest(BaseModel):
    domain: str

#class CSRGenRequest(BaseModel):
#    country: str = "US"
#    state: str = "California"
#    locality: str = "San Francisco"
#    organization: str = "My Company"
#    common_name: str

class CSRRequest(BaseModel):
    country: str
    state: str
    locality: str
    organization: str
    organizational_unit: str
    common_name: str
    email: str

class SSLConvertRequest(BaseModel):
    cert_pem: str
    to_format: str  # 'pem' or 'der'

# ----- Endpoints -----

@app.post("/api/csr-decode")
def decode_csr(data: CSRDecodeRequest):
    try:
        csr = x509.load_pem_x509_csr(data.csr.encode(), default_backend())
        return {
            "subject": csr.subject.rfc4514_string()
        }
    except Exception as e:
        return {"error": str(e)}

@app.post("/api/ssl-decode")
def decode_ssl_cert(data: SSLDecodeRequest):
    try:
        cert = x509.load_pem_x509_certificate(data.certificate.encode(), default_backend())
        return {
            "subject": cert.subject.rfc4514_string(),
            "issuer": cert.issuer.rfc4514_string(),
            "not_valid_before": cert.not_valid_before.isoformat(),
            "not_valid_after": cert.not_valid_after.isoformat()
        }
    except Exception as e:
        return {"error": str(e)}

#@app.post("/api/ssl-check")
#def ssl_check(data: SSLCheckRequest):
#    try:
#        ctx = ssl.create_default_context()
#        conn = ctx.wrap_socket(socket.socket(), server_hostname=data.domain)
#        conn.settimeout(5)
#        conn.connect((data.domain, 443))
#        cert = conn.getpeercert()
#        return cert
#    except Exception as e:
#        return {"error": str(e)}

@app.post("/api/ssl-check")
async def ssl_check(payload: dict):
    import ssl
    import socket
    from datetime import datetime

    hostname = payload.get("domain", "").strip()
    port = int(payload.get("port", 443))

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

                # Parse validity
                valid_from = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                valid_to = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                now = datetime.utcnow()
                expired = now > valid_to

                # Extract Issuer details in readable form
                issuer_parts = []
                for item in cert.get("issuer", []):
                    if isinstance(item, tuple):
                        issuer_parts.extend([f"{k}={v}" for (k, v) in item])
                issuer_str = ", ".join(issuer_parts)

                return {
                    "issuer": issuer_str,
                    "valid_from": valid_from.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "valid_to": valid_to.strftime("%Y-%m-%d %H:%M:%S UTC"),
                    "expired": expired
                }

    except Exception as e:
        return {"error": str(e)}

#@app.post("/api/csr-generator")
#def generate_csr(data: CSRGenRequest):
#    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
#    subject = x509.Name([
#        x509.NameAttribute(NameOID.COUNTRY_NAME, data.country),
#        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data.state),
#        x509.NameAttribute(NameOID.LOCALITY_NAME, data.locality),
#        x509.NameAttribute(NameOID.ORGANIZATION_NAME, data.organization),
#        x509.NameAttribute(NameOID.COMMON_NAME, data.common_name),
#    ])
#    csr = x509.CertificateSigningRequestBuilder().subject_name(subject).sign(key, hashes.SHA256())
#
#    return {
#        "private_key": key.private_bytes(
#            encoding=serialization.Encoding.PEM,
#            format=serialization.PrivateFormat.TraditionalOpenSSL,
#            encryption_algorithm=serialization.NoEncryption()
#        ).decode(),
#        "csr": csr.public_bytes(serialization.Encoding.PEM).decode()
#    }

@app.post("/api/csr-generate")
async def generate_csr(data: CSRRequest):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, data.country),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, data.state),
        x509.NameAttribute(NameOID.LOCALITY_NAME, data.locality),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, data.organization),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, data.organizational_unit),
        x509.NameAttribute(NameOID.COMMON_NAME, data.common_name),
        x509.NameAttribute(NameOID.EMAIL_ADDRESS, data.email),
    ])

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(key, hashes.SHA256())
    )

    private_key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode()

    return {
        "private_key": private_key_pem,
        "csr": csr_pem
    }

@app.post("/api/ssl-convert")
async def ssl_convert(
    file: UploadFile = File(...),
    from_format: str = Form(...),
    to_format: str = Form(...),
    password: str = Form(default="")
):
    try:
        with tempfile.TemporaryDirectory() as tmpdir:
            input_path = os.path.join(tmpdir, "input")
            output_path = os.path.join(tmpdir, "output")

            contents = await file.read()
            with open(input_path, "wb") as f:
                f.write(contents)

            cmd = []

            # PFX to PEM
            if from_format == "pfx" and to_format == "pem":
                cmd = [
                    "openssl", "pkcs12",
                    "-in", input_path,
                    "-out", output_path,
                    "-nodes", "-password", f"pass:{password}"
                ]
            # PEM to PFX
            elif from_format == "pem" and to_format == "pfx":
                cmd = [
                    "openssl", "pkcs12",
                    "-export",
                    "-in", input_path,
                    "-out", output_path,
                    "-password", f"pass:{password}"
                ]
            else:
                return {"error": "Unsupported conversion."}

            result = subprocess.run(cmd, stderr=subprocess.PIPE)
            if result.returncode != 0:
                return {"error": result.stderr.decode()}

            with open(output_path, "rb") as f:
                output_data = f.read()

            encoded = base64.b64encode(output_data).decode()
            return { "converted_cert": encoded }

    except Exception as e:
        return { "error": str(e) }
