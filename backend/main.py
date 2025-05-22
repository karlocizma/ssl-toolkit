# backend/main.py

from fastapi import FastAPI, UploadFile, File, Form
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto
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

from fastapi import UploadFile, File, Form
from fastapi.responses import StreamingResponse
import os
import tempfile
from OpenSSL import crypto

@app.post("/api/convert-ssl")
async def convert_ssl(
    file: UploadFile = File(...),
    target_format: str = Form(...),
    password: str = Form(default="")
):
    input_file = tempfile.NamedTemporaryFile(delete=False)
    input_file.write(await file.read())
    input_file.close()

    try:
        with open(input_file.name, 'rb') as f:
            content = f.read()

        try:
            cert = crypto.load_certificate(crypto.FILETYPE_PEM, content)
            key = None
        except:
            try:
                p12 = crypto.load_pkcs12(content)
                cert = p12.get_certificate()
                key = p12.get_privatekey()
            except:
                raise Exception("Unsupported certificate format or corrupted file.")

        output_file = tempfile.NamedTemporaryFile(delete=False)

        if target_format == "pem":
            pem_data = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
            output_file.write(pem_data)
        elif target_format == "pfx":
            if not key:
                raise Exception("PFX conversion requires a private key.")
            p12 = crypto.PKCS12()
            p12.set_certificate(cert)
            p12.set_privatekey(key)
            export = p12.export(passphrase=password.encode() if password else None)
            output_file.write(export)
        else:
            raise Exception("Unsupported output format.")

        output_file.close()
        return StreamingResponse(open(output_file.name, 'rb'), media_type="application/octet-stream")

    finally:
        os.unlink(input_file.name)