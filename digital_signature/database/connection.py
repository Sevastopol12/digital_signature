import os
from sqlalchemy import create_engine


class Settings:
    connection_string: str = os.getenv["DATABASE_URI"]
    conn = create_engine(url=connection_string)


db_settings = Settings()
