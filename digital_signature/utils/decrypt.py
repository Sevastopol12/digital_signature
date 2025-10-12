import base64
from typing import Dict, Any
from .helper import (
    canonicalize_metadata,
    load_transaction,
    load_public_keys,
    sha256_digest,
)
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.padding import PSS, MGF1
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


def rsa_verify(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    """
    Verify RSA-PSS
    """
    public_key = serialization.load_pem_public_key(
        public_pem, backend=default_backend()
    )
    try:
        public_key.verify(
            signature,
            message,
            PSS(mgf=MGF1(hashes.SHA256()), salt_length=hashes.SHA256().digest_size),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False


def ecdsa_verify(public_pem: bytes, message: bytes, signature: bytes) -> bool:
    public_key = serialization.load_pem_public_key(
        public_pem, backend=default_backend()
    )
    try:
        public_key.verify(signature, message, ec.ECDSA(hashes.SHA256()))
        return True
    except InvalidSignature:
        return False


def verify_signed_product_payload(payload: Dict) -> bool:
    """
    Xác thực payload do sign_product tạo ra.
    Trả về True/False
    """
    metadata = payload.get("metadata", {})
    if not metadata:
        return False
    signature_b64 = payload.get("signature", None)
    pub_b64 = payload.get("pubkey", None)
    algorithm = payload.get("algorithm", "RSA")
    signature = base64.b64decode(signature_b64)
    public_pem = base64.b64decode(pub_b64)
    message = canonicalize_metadata(metadata)

    if algorithm == "RSA":
        return rsa_verify(public_pem, message, signature)
    elif algorithm == "ECDSA":
        return ecdsa_verify(public_pem, message, signature)
    else:
        raise ValueError("Unsupported algorithm for verification")


def authenticate_author_key(author: str) -> bool:
    if not author:
        return False
    transaction_data: Dict[str, Any] = load_transaction()
    transaction_public_key: bytes = base64.b64decode(
        transaction_data.get("pubkey", None)
    )

    transaction_key_fingerprint: str = sha256_digest(data=transaction_public_key)

    _, public_key_fingerprint = load_public_keys(author=author)
    return public_key_fingerprint == transaction_key_fingerprint
