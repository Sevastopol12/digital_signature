import reflex as rx


def go_back() -> rx.Component:
    return rx.fragment(
        rx.link(
            rx.text(rx.icon("arrow-left", size=20)),
            on_click=rx.redirect("/"),
            color_scheme="violet",
        ),
        align_self="top",
        justify="start",
    )


def to_recipient() -> rx.Component:
    return rx.fragment(
        rx.link(
            rx.text(rx.icon("arrow-right", size=20)),
            on_click=rx.redirect("/recipient"),
            color_scheme="violet",
        ),
        align_self="top",
        justify="start",
    )


def to_sender() -> rx.Component:
    return rx.fragment(
        rx.link(
            rx.text(rx.icon("arrow-right", size=20)),
            on_click=rx.redirect("/sender"),
            color_scheme="violet",
        ),
        align_self="top",
        justify="start",
    )
