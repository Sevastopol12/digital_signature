import reflex as rx

config = rx.Config(
    app_name="digital_signature",
    plugins=[
        rx.plugins.SitemapPlugin(),
        rx.plugins.TailwindV4Plugin(),
    ]
)