"""SQLAlchemy database engine and session management."""
from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from app.config import settings

# SQLite needs this option when connections are used across FastAPI threads.
connect_args = (
    {"check_same_thread": False}
    if settings.database_url.startswith("sqlite")
    else {}
)

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """Base class inherited by SQLAlchemy models."""


def get_db() -> Generator[Session, None, None]:
    """Provide a database session for one request and always close it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
