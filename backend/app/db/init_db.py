# backend/app/db/init_db.py

from app.db.session import engine
from app.db.base_class import Base

# Import models so they are registered with Base.metadata
from app import models  # noqa: F401


def init_db() -> None:
    """
    Create all tables (development only).
    In production, replace this with Alembic migrations.
    """
    Base.metadata.create_all(bind=engine)
