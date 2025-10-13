import base64
import binascii
import json
from typing import Dict, Any
from .helper import (
    canonicalize_metadata,
    load_transaction,
    sha256_digest,
)
from ..database.connection import db_settings
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


def authenticate_author_key(public_key: str, author: str) -> bool:
    if not public_key:
        return False
    try:
        public_key_pem: bytes = base64.b64decode(public_key)
        public_key_fingerprint: str = sha256_digest(data=public_key_pem)

        with open(db_settings.public_key_storage, "r") as file:
            data: Dict[str, Any] = json.load(file)
            for manufacturer, keys in data.items():
                if (
                    public_key_fingerprint == keys["fingerprint"]
                    and author == manufacturer
                ):
                    return True
            return False

    except (FileNotFoundError, json.JSONDecodeError, binascii.Error):
        return False


def verify_message_digest(payload: Dict) -> bool:
    metadata = payload.get("metadata", {})
    sent_digest = payload.get("digest", None)
    if not metadata or not sent_digest:
        return False

    # Perform hash on received data & compare with sent data
    message: bytes = canonicalize_metadata(metadata)
    digest: str = sha256_digest(data=message)

    return digest == sent_digest
