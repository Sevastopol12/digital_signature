import reflex as rx
import json
from pyzbar.pyzbar import decode
from PIL import Image
from ...utils.decrypt import (
    authenticate_author_key,
    verify_signed_product_payload,
    verify_message_digest,
)
from typing import Dict, Any, List
from ...database.connection import db_settings


class AppState(rx.State):
    received_payload: Dict[str, Any] = {}
    preview_url: str = ""

    # Public key authentication
    public_key: str = ""
    manufacturer: str = ""
    key_checked: bool = False  # Detect whether the user has checked the keys or not

    # Signature
    signature: str = ""

    @rx.event
    def load_payload(self):
        with open(db_settings.transaction_storage, "r") as file:
            data = json.load(file)

        self.received_payload = data
        self.public_key = self.received_payload.get("pubkey", "")
        self.signature = self.received_payload.get("signature", "")
        self.manufacturer = self.received_payload.get("metadata", {}).get(
            "manufacturer", ""
        )

    @rx.event
    async def upload_qr(self, files: List[rx.UploadFile]):
        """Decode uploaded QR image"""
        for file in files:
            upload_dir = rx.get_upload_dir()

            upload_dir.mkdir(parents=True, exist_ok=True)
            path = upload_dir / file.name

            with open(path, "wb") as f:
                f.write(await file.read())
            self.preview_url = f"/{path}"

            img = Image.open(path)
            decoded = decode(img)
            value = decoded[0].data.decode("ascii")

            data = json.loads(value)
            self.received_payload = data
            self.public_key = self.received_payload.get("pubkey", "")
            self.signature = self.received_payload.get("signature", "")
            self.manufacturer = self.received_payload.get("metadata", {}).get(
                "manufacturer", ""
            )
            self.key_checked = True

    @rx.event
    def set_input_key(self, value: str):
        self.input_key = value

    @rx.var
    def authenticate_public_key(self) -> bool:
        if self.public_key and self.manufacturer:
            return authenticate_author_key(
                public_key=self.public_key, author=self.manufacturer
            )
        return False

    @rx.var
    def verify_digest(self) -> bool:
        return verify_message_digest(payload=self.received_payload)

    @rx.var
    def verify_signature(self) -> bool:
        if (
            verify_signed_product_payload(payload=self.received_payload)
            and self.verify_digest
        ):
            return True

        return False

    @rx.event
    def set_key_checked(self):
        if not self.key_checked:
            self.key_checked = True

    @rx.event
    def set_public_key(self, value: str):
        self.public_key = value

    @rx.var
    def payload_meta(self) -> Dict[str, Any]:
        return self.received_payload.get("metadata", {})

    @rx.var
    def payload_authority(self) -> Dict[str, Any]:
        author_metadata: List[str] = [
            "signature",
            "pubkey",
            "pubkey_fingerprint",
            "algorithm",
            "signed_at",
        ]
        return {key: self.received_payload.get(key, None) for key in author_metadata}
