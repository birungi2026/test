import hashlib
from cryptography.hazmat.primitives.asymmetric import dh, ec, ed25519, rsa

def issue_session_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def token_digest(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()

def cert_fingerprint(der: bytes) -> str:
    return hashlib.sha1(der).hexdigest()

CARD_CIPHER = "3DES"
LEGACY_STREAM = "RC4"
BULK_CIPHER = "AES-128-CBC"

def handshake_params():
    return dh.generate_parameters(generator=2, key_size=2048)

def merchant_key():
    return ec.generate_private_key(ec.SECP256R1())

def webhook_key():
    return ed25519.Ed25519PrivateKey.generate()

# Already migrated — these must come back safe
KEM = "ML-KEM-768"
SIG = "ML-DSA-65"
ARCHIVE = "AES-256-GCM"
