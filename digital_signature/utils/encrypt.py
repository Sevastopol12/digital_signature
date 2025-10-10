import base64
import datetime
from typing import Dict
from .helper import canonicalize_metadata, sha256_digest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.backends import default_backend


def rsa_sign(private_pem: bytes, message: bytes) -> bytes:
    """
    Sign message using RSA-PSS + SHA256
    returns: signature bytes
    """
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(
        message,
        PSS(mgf=MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
        hashes.SHA256(),
    )
    return signature


def ecdsa_sign(private_pem: bytes, message: bytes) -> bytes:
    """
    Sign the message using ECDSA with SHA256 (returns DER-encoded signature)
    """
    private_key = serialization.load_pem_private_key(
        private_pem, password=None, backend=default_backend()
    )
    signature = private_key.sign(message, ec.ECDSA(hashes.SHA256()))
    return signature


def sign_product(
    metadata: Dict,
    private_pem: bytes,
    public_pem: bytes,
    algorithm: str = "RSA",  # or 'ECDSA'
) -> Dict:
    """
    Generate payload: {
        "metadata": {...},
        "signature": base64(...),
        "pubkey": public_pem_str,
        "pubkey_fingerprint": sha256(pubkey_pem),
        "algorithm": "RSA" or "ECDSA",
        "signed_at": "ISO timestamp"
    }
    """
    message = canonicalize_metadata(metadata)
    if algorithm.upper() == "RSA":
        signature = rsa_sign(private_pem, message)
    elif algorithm.upper() == "ECDSA":
        signature = ecdsa_sign(private_pem, message)
    else:
        raise ValueError("Unsupported algorithm")

    signature_b64 = base64.b64encode(signature).decode("ascii")
    pub_b64 = base64.b64encode(public_pem).decode("ascii")
    payload = {
        "metadata": metadata,
        "signature": signature_b64,
        "pubkey": pub_b64,
        "pubkey_fingerprint": sha256_digest(public_pem),
        "algorithm": algorithm.upper(),
        "signed_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    return payload
