import json
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
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
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )

    public_pem: bytes = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem


def generate_ecdsa_keypair(curve=ec.SECP256R1()) -> Tuple[bytes, bytes]:
    """
    Generate public/private key using ECDSA (private pem bytes, public pem bytes)
    """
    private_key = ec.generate_private_key(curve, default_backend())
    priv_pem = private_key.private_bytes(
        Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()
    )
    pub_pem = private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )
    return priv_pem, pub_pem


def canonicalize_metadata(metadata: Dict) -> bytes:
    """
    Standardize message before hash/sign process: JSON sorted keys, no whitespace
    --> ensure data consistency
    """
    return json.dumps(
        metadata, separators=(",", ":"), sort_keys=True, ensure_ascii=False
    ).encode("utf-8")
