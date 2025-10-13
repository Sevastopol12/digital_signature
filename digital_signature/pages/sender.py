import reflex as rx
import json
import base64
from ..utils.helper import (
    generate_rsa_keypair,
    load_private_key,
    load_public_keys,
    register_key,
)
from ..utils.encrypt import sign_product
from ..database.connection import db_settings
from ..components.nav import go_back, to_recipient
from ..components.box import meta_box, data_viewer_box
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
        if value is not None:
            self.product_id = value

    @rx.event
    def set_batch(self, value: str):
        if value is not None:
            self.batch = value

    @rx.event
    def set_manufacturer(self, value: str):
        if value is not None:
            self.manufacturer = value

    @rx.event
    def set_origin(self, value: str):
        if value is not None:
            self.origin = value

    @rx.event
    def set_expired_date(self, value: str):
        if value is not None:
            self.expired_date = value

    @rx.event
    def set_production_date(self, value: str):
        if value is not None:
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
        public_pem, public_hashed = load_public_keys(author=self.manufacturer)
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


def input_product_info(*args, **kwargs) -> rx.Component:
    return rx.vstack(
        rx.heading("Product Info", size="7"),
        rx.hstack(
            product_common_info(kwargs["title_props"]),
            rx.spacer(),
            product_detail_info(kwargs["title_props"]),
            width="100%",
        ),
        publish_payload(**kwargs),
        width="100%",
        spacing="4",
        align="center",
    )


def product_common_info(*args):
    return (
        rx.flex(
            # Product Id
            rx.hstack(
                rx.text("Product Id:", **args[0]),
                rx.input(
                    default_value=AppState.product_id,
                    placeholder="product id....",
                    variant="classic",
                    on_change=AppState.set_product_id,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            # Production date
            rx.hstack(
                rx.text("Production date:", **args[0]),
                rx.input(
                    default_value=AppState.production_date,
                    placeholder="production date....",
                    variant="classic",
                    on_change=AppState.set_production_date,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            # Expired date
            rx.hstack(
                rx.text("Expiry date:", **args[0]),
                rx.input(
                    default_value=AppState.expiry_date,
                    placeholder="expiry date....",
                    variant="classic",
                    on_change=AppState.set_expired_date,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            direction="column",
            spacing="2",
            width="50%",
            height="auto",
        ),
    )


def product_detail_info(*args):
    return (
        rx.flex(
            # Product batch
            rx.hstack(
                rx.text("Batch:", **args[0]),
                rx.input(
                    default_value=AppState.batch,
                    placeholder="batch....",
                    variant="classic",
                    on_change=AppState.set_batch,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            # Manufacturer
            rx.hstack(
                rx.text("Manufacturer:", **args[0]),
                rx.input(
                    default_value=AppState.manufacturer,
                    placeholder="manufacturer....",
                    variant="classic",
                    on_change=AppState.set_manufacturer,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            # Origin
            rx.hstack(
                rx.text("Origin:", **args[0]),
                rx.input(
                    default_value=AppState.origin,
                    placeholder="origin....",
                    variant="classic",
                    on_change=AppState.set_origin,
                    color_scheme="violet",
                    width="70%",
                ),
                align="center",
                justify="between",
            ),
            direction="column",
            spacing="4",
            width="50%",
            height="auto",
        ),
    )


def encrypt_ui(*args, **kwargs) -> rx.Component:
    return rx.container(
        rx.flex(
            generate_keys(**kwargs),
            align="center",
            spacing="4",
            width="100%",
            direction="column",
        ),
        width="100%",
    )


def generate_keys(*args, **kwargs) -> rx.Component:
    return rx.fragment(
        rx.heading("Randomize keys", size="7"),
        rx.hstack(
            rx.button(
                "Randomize",
                **kwargs["button_props"],
                on_click=AppState.randomize_keys,
            ),
            rx.button(
                "Reset",
                **kwargs["button_props"],
                on_click=AppState.clear_keys,
            ),
            justify="center",
            spacing="3",
            width="100%",
        ),
        rx.cond(
            AppState.manufacturer != "",
            rx.fragment(),
            rx.text("Please indentify yourself before registering key pair"),
        ),
        rx.grid(
            rx.card(
                rx.text("Private Key", **kwargs["key_text_props"]),
                rx.scroll_area(
                    rx.cond(
                        AppState.private_key,
                        rx.text(
                            AppState.private_key,
                            word_break="break-all",
                            white_space="pre-wrap",
                            padding="0.5em",
                        ),
                        "N/A",
                    ),
                    **kwargs["scrollbar_props"],
                ),
            ),
            rx.card(
                rx.text("Public Key", **kwargs["key_text_props"]),
                rx.scroll_area(
                    rx.cond(
                        AppState.public_key,
                        rx.text(
                            AppState.public_key,
                            word_break="break-all",
                            white_space="pre-wrap",
                            padding="0.5em",
                        ),
                        "N/A",
                    ),
                    **kwargs["scrollbar_props"],
                ),
            ),
            rows="1",
            columns="2",
            justify="center",
            spacing="4",
        ),
    )


def publish_payload(*args, **kwargs) -> rx.Component:
    return rx.flex(
        rx.button(
            "Sign",
            **kwargs["button_props"],
            on_click=AppState.sign_payload,
        ),
        rx.cond(
            AppState.signed_payload,
            display_signed_payload(**kwargs),
            rx.fragment(),
        ),
        direction="column",
        align="center",
        spacing="4",
    )


def display_signed_payload(*args, **kwargs) -> rx.Component:
    return rx.center(
        rx.dialog.root(
            rx.dialog.trigger(
                rx.button("View payload", **kwargs["button_props"]),
            ),
            rx.dialog.content(
                rx.dialog.close(
                    rx.hstack(
                        rx.button(
                            rx.icon("x", size=20),
                            variant="ghost",
                            color_scheme="violet",
                        ),
                        width="100%",
                        justify="end",
                    ),
                ),
                rx.center(
                    rx.dialog.title(rx.heading("Payload info", size="7")),
                ),
                rx.divider(),
                rx.center(
                    rx.cond(
                        AppState.signed_payload,
                        rx.vstack(
                            rx.grid(
                                rx.foreach(
                                    AppState.payload_meta.items(),
                                    lambda item: meta_box(
                                        title=item[0],
                                        value=item[1],
                                    ),
                                ),
                                rows="3",
                                cols="2",
                                flow="column",
                                align="center",
                                justify="between",
                                spacing="2",
                                width="100%",
                            ),
                            rx.divider(),
                            rx.vstack(
                                meta_box(
                                    title="Algorithm",
                                    value=AppState.payload_authority.get(
                                        "algorithm", ""
                                    ),
                                ),
                                meta_box(
                                    title="Signed at",
                                    value=AppState.payload_authority.get(
                                        "signed_at", ""
                                    ),
                                ),
                                align="center",
                                justify="center",
                                width="100%",
                            ),
                            rx.divider(),
                            rx.vstack(
                                rx.text(
                                    "Message digest",
                                    weight="bold",
                                    size="3",
                                    color_scheme="violet",
                                ),
                                data_viewer_box(
                                    AppState.payload_authority.get(
                                        "digest", "N/A"
                                    ),
                                ),
                                rx.text(
                                    "Signature",
                                    weight="bold",
                                    size="3",
                                    color_scheme="violet",
                                ),
                                data_viewer_box(
                                    AppState.payload_authority.get("signature", "N/A"),
                                ),
                                rx.text(
                                    "Public Key (Base64)",
                                    weight="bold",
                                    size="3",
                                    color_scheme="violet",
                                ),
                                data_viewer_box(
                                    AppState.payload_authority.get("pubkey", "N/A"),
                                ),
                                paddingTop="1em",
                                align_items="start",
                                spacing="2",
                                width="100%",
                            ),
                            rx.divider(),
                            width="100%",
                        ),
                        rx.text("No payload signed."),
                    ),
                    paddingTop="2em",
                ),
            ),
            align="center",
        ),
    )


@rx.page(route="/sender")
def index() -> rx.Component:
    params = {
        "button_props": {
            "variant": "solid",
            "color_scheme": "violet",
            "size": "2",
            "radius": "medium",
        },
        "key_text_props": {"weight": "medium", "color_scheme": "violet"},
        "scrollbar_props": {
            "height": "5vw",
            "width": "25vw",
            "type": "hover",
            "scrollbars": "both",
        },
        "title_props": {"weight": "medium", "color_scheme": "violet"},
    }
    return rx.container(
        rx.hstack(go_back(), rx.spacer(), to_recipient(), width="100%"),
        rx.center(
            rx.flex(
                rx.card(encrypt_ui(**params), flex="1", width="100%"),
                rx.card(
                    input_product_info(**params),
                    flex="1",
                    width="100%",
                    padding="1em",
                ),
                direction="column",
                align="center",
                spacing="5",
                justify="between",
            ),
            width="100%",
            paddingTop="2em",
            height="auto",
        ),
        width="100%",
    )
