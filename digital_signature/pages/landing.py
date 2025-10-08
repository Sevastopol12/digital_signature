import reflex as rx


@rx.page(route="/")
def index():
    return rx.center(
        rx.vstack(
            rx.button(
                "Sender",
                variant="outline",
                on_click=rx.redirect("/sender"),
            ),
            rx.button(
                "Recipient",
                variant="outline",
                on_click=rx.redirect("/recipient"),
            ),
            align="center",
            justify="between",
        ),
        paddingTop="20em",
        height="100%",
        width="100%",
    )
