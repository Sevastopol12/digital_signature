import reflex as rx
import json
import base64
from ...utils.helper import (
    generate_rsa_keypair,
    load_private_key,
    load_public_keys,
    register_key,
    generate_qr,
)
from ...utils.encrypt import sign_product
from ...database.connection import db_settings
from typing import Dict, Any, List


class AppState(rx.State):
    # Message metadata
    product_id: str = "SKU-12345"
    batch: str = "BATCH-2025-09-30"
    manufacturer: str = "ACME FOOD JSC"
    origin: str = "Viet Name"
    production_date: str = "2025-09-30"
    expiry_date: str = "2026-09-30"
    certificate: Dict[str, Any]

    # Keys
    private_key: str = ""
    public_key: str = ""

    # Settings
    algorithms: List[str] = ["rsa", "ecdsa"]
    selected_algorithm: str = "rsa"

    # Payload
    signed_payload: Dict[str, Any] = {}

    @rx.event
    def set_product_id(self, value: str):
        self.product_id = value

    @rx.event
    def set_batch(self, value: str):
        self.batch = value

    @rx.event
    def set_manufacturer(self, value: str):
        if value is not None:
            self.manufacturer = value

    @rx.event
    def set_origin(self, value: str):
        self.origin = value

    @rx.event
    def set_expired_date(self, value: str):
        self.expiry_date = value

    @rx.event
    def set_production_date(self, value: str):
        self.production_date = value

    @rx.event
    def randomize_keys(self) -> None:
        if self.manufacturer != "":
            pem_private, pem_public = generate_rsa_keypair(key_size=3072)
            register_key(
                private_key_pem=pem_private,
                public_key_pem=pem_public,
                author=self.manufacturer,
            )
            self.private_key = base64.b64encode(pem_private).decode("ascii")
            self.public_key = base64.b64encode(pem_public).decode("ascii")
        else:
            return None

    @rx.event
    def clear_keys(self):
        self.private_key = ""
        self.public_key = ""

    @rx.event
    def sign_payload(self):
        public_pem, _ = load_public_keys(author=self.manufacturer)
        private_pem = load_private_key(author=self.manufacturer)

        product_payload: Dict[str, Any] = {
            "product_id": self.product_id,
            "batch": self.batch,
            "manufacturer": self.manufacturer,
            "origin": self.origin,
            "production_date": self.production_date,
            "expiry_date": self.expiry_date,
        }

        self.signed_payload: Dict[str, Any] = sign_product(
            metadata=product_payload,
            private_pem=private_pem,
            public_pem=public_pem,
            algorithm=self.selected_algorithm,
        )

        self.publish_product()

    def publish_product(self) -> None:
        if self.signed_payload:
            with open(db_settings.transaction_storage, "w", encoding="utf-8") as file:
                json.dump(self.signed_payload, file, indent=4)

    @rx.var
    def generate_qr(self) -> str:
        return generate_qr(self.signed_payload)

    @rx.var
    def payload_meta(self) -> Dict[str, Any]:
        return self.signed_payload.get("metadata", {})

    @rx.var
    def payload_authority(self) -> Dict[str, Any]:
        author_metadata: List[str] = [
            "signature",
            "digest",
            "pubkey",
            "pubkey_fingerprint",
            "algorithm",
            "signed_at",
        ]
        return {key: self.signed_payload.get(key, None) for key in author_metadata}
