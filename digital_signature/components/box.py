import reflex as rx


def meta_box(title: str, value: str, *args, **kwargs) -> rx.Component:
    return rx.hstack(
        rx.text(
            rx.cond(
                title,
                f"{title.replace('_', ' ').capitalize()}: ",
                "N/A: ",
            ),
            size="3",
            color_scheme="violet",
            weight="bold"
        ),
        rx.text(
            rx.cond(
                value,
                value,
                "N/A",
            ),
        ),
        width="100%",
        align="center",
        justify="start",
    )


def data_viewer_box(
    content: str, width: str = "36vw", height: str = "4vw"
) -> rx.Component:
    """Creates a container for long, fixed-width data (like keys/signatures)"""
    return rx.vstack(
        rx.card(
            rx.scroll_area(
                rx.text(
                    content,
                    white_space="pre-wrap",
                    word_break="break-all",
                    padding="0.5em",
                ),
                width=width,
                height=height,
            ),
        ),
    )
