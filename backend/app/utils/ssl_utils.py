import os
import tempfile
import base64
import hashlib
from datetime import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, SignatureAlgorithmOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import pkcs12
import OpenSSL
import validators

def clean_pem_data(pem_data):
    """Clean and validate PEM data"""
    if isinstance(pem_data, bytes):
        pem_data = pem_data.decode('utf-8')
    
    # Remove extra whitespace and ensure proper line endings
    lines = [line.strip() for line in pem_data.split('\n') if line.strip()]
    
    # Ensure proper PEM structure
    cleaned_lines = []
    for line in lines:
        # Skip empty lines
        if not line:
            continue
        # Add proper line breaks for PEM headers/footers
        cleaned_lines.append(line)
    
    result = '\n'.join(cleaned_lines)
    
    # Add final newline if missing
    if not result.endswith('\n'):
        result += '\n'
    
    return result

def get_certificate_info(cert_data):
    """Extract detailed information from a certificate"""
    try:
        if isinstance(cert_data, str):
            # Clean the PEM data first
            cert_data = clean_pem_data(cert_data)
            cert_data = cert_data.encode('utf-8')
        
        # Try to load the certificate with better error handling
        try:
            cert = x509.load_pem_x509_certificate(cert_data)
        except ValueError as e:
            if "Could not deserialize" in str(e) or "Unable to load PEM file" in str(e):
                raise ValueError("Invalid PEM format. Please ensure the certificate is properly formatted with correct BEGIN/END markers and valid base64 encoding.")
            else:
                raise ValueError(f"Unable to load PEM file. {str(e)}. See https://cryptography.io/en/latest/faq/#why-can-t-i-import-my-pem-file for more details.")
        
        # Basic certificate information
        subject = cert.subject
        issuer = cert.issuer
        
        # Extract common name
        subject_cn = None
        issuer_cn = None
        
        for attribute in subject:
            if attribute.oid == NameOID.COMMON_NAME:
                subject_cn = attribute.value
                break
        
        for attribute in issuer:
            if attribute.oid == NameOID.COMMON_NAME:
                issuer_cn = attribute.value
                break
        
        # Get SAN (Subject Alternative Names)
        san_list = []
        try:
            san_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
            san_list = [name.value for name in san_ext.value]
        except x509.ExtensionNotFound:
            pass
        
        # Get key usage
        key_usage = []
        try:
            ku_ext = cert.extensions.get_extension_for_oid(x509.oid.ExtensionOID.KEY_USAGE)
            ku = ku_ext.value
            if ku.digital_signature:
                key_usage.append('Digital Signature')
            if ku.key_cert_sign:
                key_usage.append('Certificate Sign')
            if ku.key_encipherment:
                key_usage.append('Key Encipherment')
            if ku.data_encipherment:
                key_usage.append('Data Encipherment')
            if ku.key_agreement:
                key_usage.append('Key Agreement')
            if ku.crl_sign:
                key_usage.append('CRL Sign')
        except x509.ExtensionNotFound:
            pass
        
        # Calculate fingerprints
        cert_der = cert.public_bytes(serialization.Encoding.DER)
        sha1_fingerprint = hashlib.sha1(cert_der).hexdigest().upper()
        sha256_fingerprint = hashlib.sha256(cert_der).hexdigest().upper()
        
        # Format fingerprints with colons
        sha1_fingerprint = ':'.join([sha1_fingerprint[i:i+2] for i in range(0, len(sha1_fingerprint), 2)])
        sha256_fingerprint = ':'.join([sha256_fingerprint[i:i+2] for i in range(0, len(sha256_fingerprint), 2)])
        
        return {
            'subject': {
                'common_name': subject_cn,
                'country': get_name_attribute(subject, NameOID.COUNTRY_NAME),
                'state': get_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME),
                'locality': get_name_attribute(subject, NameOID.LOCALITY_NAME),
                'organization': get_name_attribute(subject, NameOID.ORGANIZATION_NAME),
                'organizational_unit': get_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
                'email': get_name_attribute(subject, NameOID.EMAIL_ADDRESS)
            },
            'issuer': {
                'common_name': issuer_cn,
                'country': get_name_attribute(issuer, NameOID.COUNTRY_NAME),
                'state': get_name_attribute(issuer, NameOID.STATE_OR_PROVINCE_NAME),
                'locality': get_name_attribute(issuer, NameOID.LOCALITY_NAME),
                'organization': get_name_attribute(issuer, NameOID.ORGANIZATION_NAME),
                'organizational_unit': get_name_attribute(issuer, NameOID.ORGANIZATIONAL_UNIT_NAME)
            },
            'validity': {
                'not_before': cert.not_valid_before.isoformat(),
                'not_after': cert.not_valid_after.isoformat(),
                'is_expired': cert.not_valid_after < datetime.now(),
                'days_until_expiry': (cert.not_valid_after - datetime.now()).days
            },
            'public_key': {
                'algorithm': cert.public_key().__class__.__name__,
                'key_size': get_key_size(cert.public_key())
            },
            'signature_algorithm': cert.signature_algorithm_oid._name,
            'serial_number': str(cert.serial_number),
            'version': cert.version.name,
            'subject_alternative_names': san_list,
            'key_usage': key_usage,
            'fingerprints': {
                'sha1': sha1_fingerprint,
                'sha256': sha256_fingerprint
            }
        }
    except Exception as e:
        raise ValueError(f"Error parsing certificate: {str(e)}")

def get_name_attribute(name, oid):
    """Get a specific attribute from a certificate name"""
    for attribute in name:
        if attribute.oid == oid:
            return attribute.value
    return None

def get_key_size(public_key):
    """Get the key size for different key types"""
    if hasattr(public_key, 'key_size'):
        return public_key.key_size
    elif hasattr(public_key, 'curve'):
        return public_key.curve.key_size
    return None

def get_csr_info(csr_data):
    """Extract information from a Certificate Signing Request"""
    try:
        if isinstance(csr_data, str):
            csr_data = csr_data.encode('utf-8')
        
        csr = x509.load_pem_x509_csr(csr_data)
        
        subject = csr.subject
        subject_cn = None
        
        for attribute in subject:
            if attribute.oid == NameOID.COMMON_NAME:
                subject_cn = attribute.value
                break
        
        # Get SAN from CSR
        san_list = []
        try:
            for ext in csr.extensions:
                if ext.oid == x509.oid.ExtensionOID.SUBJECT_ALTERNATIVE_NAME:
                    san_list = [name.value for name in ext.value]
                    break
        except:
            pass
        
        return {
            'subject': {
                'common_name': subject_cn,
                'country': get_name_attribute(subject, NameOID.COUNTRY_NAME),
                'state': get_name_attribute(subject, NameOID.STATE_OR_PROVINCE_NAME),
                'locality': get_name_attribute(subject, NameOID.LOCALITY_NAME),
                'organization': get_name_attribute(subject, NameOID.ORGANIZATION_NAME),
                'organizational_unit': get_name_attribute(subject, NameOID.ORGANIZATIONAL_UNIT_NAME),
                'email': get_name_attribute(subject, NameOID.EMAIL_ADDRESS)
            },
            'public_key': {
                'algorithm': csr.public_key().__class__.__name__,
                'key_size': get_key_size(csr.public_key())
            },
            'signature_algorithm': csr.signature_algorithm_oid._name,
            'subject_alternative_names': san_list
        }
    except Exception as e:
        raise ValueError(f"Error parsing CSR: {str(e)}")

def generate_private_key(key_type='RSA', key_size=2048, curve_name='secp256r1'):
    """Generate a private key"""
    if key_type.upper() == 'RSA':
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=int(key_size)
        )
    elif key_type.upper() == 'EC':
        if curve_name == 'secp256r1':
            curve = ec.SECP256R1()
        elif curve_name == 'secp384r1':
            curve = ec.SECP384R1()
        elif curve_name == 'secp521r1':
            curve = ec.SECP521R1()
        else:
            curve = ec.SECP256R1()
        
        private_key = ec.generate_private_key(curve)
    else:
        raise ValueError("Unsupported key type")
    
    return private_key

def generate_csr(subject_data, private_key, san_list=None):
    """Generate a Certificate Signing Request"""
    # Build subject name
    subject_name_list = []
    
    if subject_data.get('country'):
        subject_name_list.append(x509.NameAttribute(NameOID.COUNTRY_NAME, subject_data['country']))
    if subject_data.get('state'):
        subject_name_list.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, subject_data['state']))
    if subject_data.get('locality'):
        subject_name_list.append(x509.NameAttribute(NameOID.LOCALITY_NAME, subject_data['locality']))
    if subject_data.get('organization'):
        subject_name_list.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['organization']))
    if subject_data.get('organizational_unit'):
        subject_name_list.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data['organizational_unit']))
    if subject_data.get('common_name'):
        subject_name_list.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data['common_name']))
    if subject_data.get('email'):
        subject_name_list.append(x509.NameAttribute(NameOID.EMAIL_ADDRESS, subject_data['email']))
    
    subject = x509.Name(subject_name_list)
    
    # Build CSR
    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(subject)
    
    # Add SAN extension if provided
    if san_list:
        san_names = []
        for san in san_list:
            if validators.domain(san):
                san_names.append(x509.DNSName(san))
            elif validators.email(san):
                san_names.append(x509.RFC822Name(san))
            elif validators.ipv4(san) or validators.ipv6(san):
                san_names.append(x509.IPAddress(san))
        
        if san_names:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_names),
                critical=False
            )
    
    # Sign CSR
    csr = builder.sign(private_key, hashes.SHA256())
    
    return csr

def convert_certificate_format(cert_data, input_format, output_format, password=None, private_key_data=None):
    """Convert certificate between different formats"""
    try:
        if input_format.upper() == 'PEM' and output_format.upper() == 'DER':
            cert = x509.load_pem_x509_certificate(cert_data)
            return cert.public_bytes(serialization.Encoding.DER)
        
        elif input_format.upper() == 'DER' and output_format.upper() == 'PEM':
            cert = x509.load_der_x509_certificate(cert_data)
            return cert.public_bytes(serialization.Encoding.PEM)
        
        elif input_format.upper() == 'PEM' and output_format.upper() == 'PFX':
            # Load certificate
            cert = x509.load_pem_x509_certificate(cert_data)
            
            # Load private key if provided
            private_key = None
            if private_key_data:
                if isinstance(private_key_data, str):
                    private_key_data = private_key_data.encode('utf-8')
                private_key = serialization.load_pem_private_key(private_key_data, password=None)
            
            # Parse additional certificates from PEM data if present
            additional_certs = []
            if isinstance(cert_data, bytes):
                cert_data_str = cert_data.decode('utf-8')
            else:
                cert_data_str = cert_data
            
            # Look for multiple certificates in the PEM data
            cert_blocks = cert_data_str.split('-----BEGIN CERTIFICATE-----')[1:]
            if len(cert_blocks) > 1:
                # Skip the first one (already loaded as main cert)
                for cert_block in cert_blocks[1:]:
                    try:
                        cert_pem = '-----BEGIN CERTIFICATE-----' + cert_block
                        additional_cert = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
                        additional_certs.append(additional_cert)
                    except:
                        continue
            
            # Set password for PFX
            pfx_password = password.encode('utf-8') if password else b''
            
            # Create PFX
            pfx_data = pkcs12.serialize_key_and_certificates(
                name=b'Certificate',
                key=private_key,
                cert=cert,
                cas=additional_certs if additional_certs else None,
                encryption_algorithm=serialization.BestAvailableEncryption(pfx_password) if password else serialization.NoEncryption()
            )
            
            return pfx_data
        
        elif input_format.upper() == 'PFX' and output_format.upper() == 'PEM':
            if password:
                password = password.encode('utf-8')
            
            private_key, cert, additional_certs = pkcs12.load_key_and_certificates(
                cert_data, password
            )
            
            result = []
            
            # Add private key
            if private_key:
                private_pem = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                result.append(private_pem.decode('utf-8'))
            
            # Add certificate
            if cert:
                cert_pem = cert.public_bytes(serialization.Encoding.PEM)
                result.append(cert_pem.decode('utf-8'))
            
            # Add additional certificates
            if additional_certs:
                for add_cert in additional_certs:
                    add_cert_pem = add_cert.public_bytes(serialization.Encoding.PEM)
                    result.append(add_cert_pem.decode('utf-8'))
            
            return '\n'.join(result).encode('utf-8')
        
        else:
            raise ValueError(f"Conversion from {input_format} to {output_format} not supported")
    
    except Exception as e:
        raise ValueError(f"Error converting certificate: {str(e)}")

def validate_private_key(key_data, password=None):
    """Validate and get information about a private key"""
    try:
        if isinstance(key_data, str):
            key_data = key_data.encode('utf-8')
        
        if password:
            password = password.encode('utf-8')
        
        try:
            # Try to load as encrypted key
            private_key = serialization.load_pem_private_key(key_data, password=password)
        except:
            # Try to load as unencrypted key
            private_key = serialization.load_pem_private_key(key_data, password=None)
        
        key_info = {
            'algorithm': private_key.__class__.__name__,
            'key_size': get_key_size(private_key),
            'is_encrypted': password is not None
        }
        
        return key_info
    
    except Exception as e:
        raise ValueError(f"Error validating private key: {str(e)}")

def check_key_certificate_match(private_key_data, certificate_data, key_password=None):
    """Check if a private key matches a certificate"""
    try:
        # Load private key
        if isinstance(private_key_data, str):
            private_key_data = private_key_data.encode('utf-8')
        
        if key_password:
            key_password = key_password.encode('utf-8')
        
        private_key = serialization.load_pem_private_key(private_key_data, password=key_password)
        
        # Load certificate
        if isinstance(certificate_data, str):
            certificate_data = certificate_data.encode('utf-8')
        
        certificate = x509.load_pem_x509_certificate(certificate_data)
        
        # Compare public keys
        private_public_key = private_key.public_key()
        cert_public_key = certificate.public_key()
        
        # Serialize both public keys to compare
        private_public_pem = private_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        cert_public_pem = cert_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_public_pem == cert_public_pem
    
    except Exception as e:
        raise ValueError(f"Error checking key-certificate match: {str(e)}")

