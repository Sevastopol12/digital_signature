import json
from ..database.connection import db_settings
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    BestAvailableEncryption
)
from cryptography.hazmat.backends import default_backend


def generate_rsa_keypair(key_size: int = 3072) -> Tuple[bytes, bytes]:
    """
    Generate public/private key using RSA. Transform these keys into PEM format for portability as well as readability
    """
    private_key: RSAPrivateKey = rsa.generate_private_key(
        public_exponent=65537, key_size=key_size, backend=default_backend()
    )

    private_pem: bytes = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )

    public_pem: bytes = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    store_keys(private_pem, public_pem)
    return private_pem, public_pem


def generate_ecdsa_keypair(curve=ec.SECP256R1()) -> Tuple[bytes, bytes]:
    """
    Generate public/private key using ECDSA (private pem bytes, public pem bytes)
    """
    private_key = ec.generate_private_key(curve, default_backend())
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


def canonicalize_metadata(metadata: Dict) -> bytes:
    """
    Standardize message before hash/sign process: JSON sorted keys, no whitespace
    --> ensure data consistency
    """
    return json.dumps(
        metadata, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")


def store_keys(private_key_pem: bytes, public_key_pem: bytes) -> None:
    with open(db_settings.private_storage, "wb") as file:
        file.write(private_key_pem)
    with open(db_settings.public_storage, "wb") as file:
        file.write(public_key_pem)


def load_keys() -> Tuple[bytes, bytes]:
    with open(db_settings.private_storage, "rb") as file:
        private_pem: bytes = file.read()
    with open(db_settings.public_storage, "rb") as file:
        public_pem: bytes = file.read()

    return private_pem, public_pem
