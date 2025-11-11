import reflex as rx
import json
from pyzbar.pyzbar import decode
from PIL import Image
from ..utils.decrypt import (
    authenticate_author_key,
    verify_signed_product_payload,
    verify_message_digest,
)
from typing import Dict, Any, List
from ..database.connection import db_settings
from ..components.nav import go_back, to_sender
from ..components.box import meta_box, data_viewer_box


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
        """Decode uploaded QR image."""
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


def display_metadata(*args, **kwargs) -> rx.Component:
    return rx.fragment(
        rx.grid(
            rx.foreach(
                AppState.payload_meta.items(),
                lambda item: meta_box(title=item[0], value=item[1], **kwargs),
            ),
            rows="3",
            cols="2",
            flow="column",
            align="center",
            justify="between",
            spacing="3",
            width="100%",
        ),
    )


def display_author(*args, **kwargs) -> rx.Component:
    return rx.fragment(
        rx.vstack(
            meta_box(
                title="Algorithm",
                value=AppState.payload_authority.get("algorithm", ""),
            ),
            meta_box(
                title="Signed at",
                value=AppState.payload_authority.get("signed_at", ""),
            ),
            align="center",
            justify="center",
            width="100%",
        ),
    )


def display_payload_info():
    return rx.fragment(
        rx.vstack(
            rx.text(
                "Signature",
                weight="bold",
                size="3",
                color_scheme="violet",
            ),
            data_viewer_box(
                AppState.payload_authority.get("signature", "N/A"),
                width="100%",
                height="5vw",
            ),
            rx.text(
                "Public Key (Base64)",
                weight="bold",
                size="3",
                color_scheme="violet",
            ),
            data_viewer_box(
                AppState.payload_authority.get("pubkey", "N/A"),
                width="100%",
                height="5vw",
            ),
            align_items="start",
            spacing="2",
            width="100%",
        ),
    )


def product_info() -> rx.Component:
    return rx.flex(
        rx.button(
            rx.text("Load file"),
            on_click=[AppState.load_payload, AppState.set_key_checked],
        ),
        rx.heading("OR", size="5"),
        rx.vstack(
            # Upload input
            rx.upload(
                rx.cond(
                    AppState.preview_url != "",
                    rx.image(
                        src=AppState.preview_url,
                        width="250px",
                        border_radius="md",
                        border="1px solid gray",
                    ),
                    rx.vstack(
                        rx.text("Upload files"),
                        rx.icon(tag="upload"),
                        align="center",
                    ),
                ),
                id="upload",
                on_drop=AppState.upload_qr(rx.upload_files("upload")),
            ),
            align="center",
            width="100%",
        ),
        rx.cond(
            AppState.key_checked,
            rx.fragment(
                display_metadata(),
                rx.divider(),
                display_author(),
                rx.divider(),
                display_payload_info(),
            ),
            rx.hstack(
                "Load a sample to further verify it",
                width="100%",
                justify="center",
            ),
        ),
        paddingTop="1em",
        direction="column",
        spacing="4",
        align="center",
        width="40vw",
    )


def public_key_authenticate(*args, **kwargs) -> rx.Component:
    return rx.flex(
        rx.fragment(
            rx.text("Public key (fingerprint comparison)", **kwargs["title_props"]),
            rx.scroll_area(
                rx.text_area(
                    AppState.public_key,
                    white_space="pre-wrap",
                    word_break="break-all",
                    padding="0.5em",
                    on_change=AppState.set_public_key,
                    width="100%",
                    height="100%",
                ),
                width="37vw",
                height="7vw",
            ),
        ),
        rx.hstack(
            rx.cond(
                AppState.public_key != "",
                rx.cond(
                    AppState.authenticate_public_key,
                    rx.fragment(
                        rx.text(rx.icon("circle-check", size=25), color_scheme="grass"),
                        rx.text(
                            "Valid, manufaturer matched with",
                            color_scheme="grass",
                        ),
                        rx.text(
                            f"{AppState.manufacturer}",
                            **kwargs["title_props"],
                        ),
                    ),
                    rx.fragment(
                        rx.text(rx.icon("circle-x", size=25), color_scheme="tomato"),
                        rx.text(
                            "Invalid, manufaturer does not matched with",
                            color_scheme="tomato",
                        ),
                        rx.text(
                            f"{AppState.manufacturer}",
                            **kwargs["title_props"],
                        ),
                    ),
                ),
                rx.text(
                    "Insert the public key",
                    color_scheme="gray",
                ),
            ),
            width="100%",
            align="center",
            justify="center",
            paddingTop="1em",
        ),
        direction="column",
        spacing="3",
        align="center",
    )


def verify_digest(*args, **kwargs) -> rx.Component:
    return rx.flex(
        rx.cond(
            AppState.authenticate_public_key,
            rx.fragment(
                rx.hstack(
                    rx.cond(
                        AppState.verify_digest,
                        rx.fragment(
                            rx.text(
                                rx.icon("circle-check", size=25), color_scheme="grass"
                            ),
                            rx.text(
                                "Message & digest identical. Data integrity confirmed.",
                                color_scheme="grass",
                            ),
                        ),
                        rx.fragment(
                            rx.text(
                                rx.icon("circle-x", size=25), color_scheme="tomato"
                            ),
                            rx.text(
                                "Message & digest unidentical. Data tampering detected.",
                                color_scheme="tomato",
                            ),
                        ),
                    ),
                ),
            ),
            rx.fragment(),
        ),
        direction="column",
        spacing="3",
        align="center",
    )


def verify_signature(*args, **kwargs) -> rx.Component:
    return rx.flex(
        rx.cond(
            AppState.authenticate_public_key,
            rx.fragment(
                rx.hstack(
                    rx.cond(
                        AppState.verify_signature,
                        rx.fragment(
                            rx.text(
                                rx.icon("circle-check", size=25), color_scheme="grass"
                            ),
                            rx.text(
                                "Signature is VALID. Product origin and data integrity confirmed.",
                                color_scheme="grass",
                            ),
                        ),
                        rx.fragment(
                            rx.text(
                                rx.icon("circle-x", size=25), color_scheme="tomato"
                            ),
                            rx.text(
                                "Signature is INVALID. Potential data tampering or fraudulent origin detected!",
                                color_scheme="tomato",
                            ),
                        ),
                    ),
                ),
            ),
            rx.fragment(),
        ),
        direction="column",
        spacing="3",
        align="center",
    )


def product_verification(*args, **kwargs) -> rx.Component:
    return rx.flex(
        rx.vstack(
            # Public key authentication
            public_key_authenticate(**kwargs),
            verify_digest(**kwargs),
            verify_signature(**kwargs),
            align_items="center",
            spacing="4",
            width="100%",
        ),
        width="40vw",
        paddingTop="1em",
        direction="column",
        spacing="4",
        align="center",
    )


@rx.page(route="/recipient")
def index() -> rx.Component:
    params = {
        "button_props": {
            "variant": "solid",
            "color_scheme": "violet",
            "size": "2",
            "radius": "medium",
        },
        "key_text_props": {"weight": "medium", "color_scheme": "violet"},
        "title_props": {"weight": "bold", "color_scheme": "violet", "size": "4"},
    }
    return rx.container(
        rx.hstack(go_back(), rx.spacer(), to_sender(), width="100%", align="center"),
        rx.center(
            rx.flex(
                rx.card(
                    rx.heading(
                        "Product Info", size="7", align="center", paddingBottom="0.5em"
                    ),
                    rx.divider(),
                    product_info(),
                ),
                rx.cond(
                    AppState.key_checked,
                    rx.card(
                        rx.heading(
                            "Verification",
                            size="7",
                            align="center",
                            paddingBottom="0.5em",
                        ),
                        rx.divider(),
                        product_verification(**params),
                    ),
                    rx.fragment(),
                ),
                direction="row",
                spacing="5",
                align="baseline",
            ),
            width="100%",
            paddingTop="2em",
            height="auto",
        ),
        width="100%",
    )
