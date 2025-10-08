import reflex as rx
from ..utils.helper import generate_rsa_keypair
from ..utils.encrypt import sign_product
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
    private_key: bytes = None
    public_key: bytes = None

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
    def encrypt(self):
        return 0

    @rx.event
    def randomize_keys(self):
        pem_private, pem_public = generate_rsa_keypair(key_size=1024)
        self.private_key = pem_private
        self.public_key = pem_public

    @rx.event
    def clear_keys(self):
        self.private_key = ""
        self.public_key = ""

    @rx.event
    def sign_product(self):
        if not self.private_key:
            self.signed_payload = {}
            return

        product_payload: Dict[str, Any] = {
            "product_id": self.product_id,
            "batch": self.batch,
            "manufacturer": self.manufacturer,
            "origin": self.origin,
            "production_date": self.production_date,
            "expiry_date": self.expiry_date,
            "certificate": self.certificate,
        }
        self.signed_payload: Dict[str, Any] = sign_product(
            metadata=product_payload,
            private_pem=self.private_key,
            public_pem=self.public_key,
            algorithm=self.selected_algorithm,
        )


def input_product_info(*children) -> rx.Component:
    title_props = {"weight": "medium", "color_scheme": "violet"}

    return rx.vstack(
        rx.hstack(
            product_common_info(title_props),
            rx.spacer(),
            product_detail_info(title_props),
            width="100%",
        ),
        rx.vstack(
            rx.text("Certificate:", **title_props),
            rx.input(
                variant="classic",
                color_scheme="violet",
                width="70%",
                type="file",
                height="5vw",
            ),
            width="80%",
            align="center",
        ),
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


def encrypt_ui() -> rx.Component:
    button_props = {
        "variant": "solid",
        "color_scheme": "violet",
        "size": "2",
        "radius": "medium",
    }

    key_text_props = {"weight": "medium", "color_scheme": "violet"}
    scrollbar_props = {
        "height": "2vw",
        "width": "25vw",
        "type": "hover",
        "scrollbars": "horizontal",
    }
    return rx.container(
        rx.flex(
            rx.heading("Randomize keys", size="7"),
            rx.hstack(
                rx.button(
                    "Randomize",
                    **button_props,
                    on_click=AppState.randomize_keys,
                ),
                rx.button(
                    "Reset",
                    **button_props,
                    on_click=AppState.clear_keys,
                ),
                justify="center",
                spacing="3",
                width="100%",
            ),
            rx.grid(
                rx.card(
                    rx.text("Private Key", **key_text_props),
                    rx.scroll_area(
                        rx.cond(AppState.private_key, AppState.private_key, "N/A"),
                        **scrollbar_props,
                    ),
                ),
                rx.card(
                    rx.text("Public Key", **key_text_props),
                    rx.scroll_area(
                        rx.cond(AppState.public_key, AppState.public_key, "N/A"),
                        **scrollbar_props,
                    ),
                ),
                rows="1",
                columns="2",
                justify="center",
                spacing="4",
            ),
            align="center",
            spacing="4",
            width="100%",
            direction="column",
        ),
        width="100%",
    )


@rx.page(route="/sender")
def index() -> rx.Component:
    return rx.center(
        rx.flex(
            rx.card(encrypt_ui(), flex="1", width="100%"),
            rx.card(
                input_product_info(),
                flex="1",
                width="100%",
                padding="2em",
            ),
            rx.button("Sign", on_click=AppState.sign_product),
            rx.scroll_area(
                AppState.signed_payload,
                scrollbars="horizontal",
                width="10vw",
                height="5vw",
                type="always",
            ),
            direction="column",
            align="center",
            spacing="5",
            justify="between",
        ),
        width="100%",
        paddingTop="5em",
        height="auto",
    )
