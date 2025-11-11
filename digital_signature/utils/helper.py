import json
import hashlib
import base64
import random
import string
import qrcode
import io
from qrcode.constants import ERROR_CORRECT_L
from ..database.connection import db_settings
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    # BestAvailableEncryption,
)


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


def sha256_digest(data: bytes) -> str:
    """
    Hash the message
    """
    hashed_message = hashlib.sha256(data).hexdigest()
    return hashed_message


def load_public_keys(author: str) -> Tuple[bytes, bytes]:
    with open(db_settings.public_key_storage, "r") as f:
        data = json.load(f)
        author_keys = data.get(author, None)

        if author_keys:
            public_pem = base64.b64decode(author_keys["public_key"])
            public_hashed = author_keys["fingerprint"]
        else:
            public_pem = None
            public_hashed = None

    return public_pem, public_hashed


def load_private_key(author: str) -> bytes:
    with open(db_settings.private_key_storage, "r") as f:
        data = json.load(f)
        author_keys = data.get(author, None)

        if author_keys:
            private_pem = base64.b64decode(author_keys["private_key"])
        else:
            private_pem = None

    return private_pem


def register_key(private_key_pem: bytes, public_key_pem: bytes, author: str) -> None:
    """Store author along with their keys into database"""
    public_keys: Dict[str, Any] = {
        "public_key": base64.b64encode(public_key_pem).decode("ascii"),
        "fingerprint": sha256_digest(public_key_pem),
    }
    private_keys: Dict[str, Any] = {
        "private_key": base64.b64encode(private_key_pem).decode("ascii")
    }

    store_keys(storage=db_settings.public_key_storage, keys=public_keys, author=author)
    store_keys(
        storage=db_settings.private_key_storage, keys=private_keys, author=author
    )


def store_keys(storage: str, keys: Dict[str, Any], author: str) -> None:
    try:
        with open(storage, "r", encoding="ascii") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    if data.get(author, None):
        # Update if exist
        for key, item in keys.items():
            data[author].update(keys)
    else:
        data[author] = keys

    with open(storage, "w") as file:
        json.dump(data, file, indent=4)


def load_transaction() -> Any:
    try:
        with open(db_settings.transaction_storage, "r") as file:
            data = json.load(file)
            return data
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def create_unique_filename(file_name: str):
    filename = "".join(random.choices(string.ascii_letters + string.digits, k=10))
    return filename + "_" + file_name


def generate_qr(data_dict: dict) -> bytes:
    """Generates QR code image"""
    data_string = json.dumps(data_dict, ensure_ascii=False, separators=(",", ":"))

    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
    )
    qr.add_data(data_string)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    byte_io = io.BytesIO()
    img.save(byte_io, format="PNG")

    base64_encoded_data = base64.b64encode(byte_io.getvalue()).decode("utf-8")
    return f"data:image/png;base64,{base64_encoded_data}"
