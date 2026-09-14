import os
import logging
from pathlib import Path
from typing import Generator
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker, declarative_base

logger = logging.getLogger("satyaai.database")

# Load environment variables from .env in project root
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
if env_path.exists():
    load_dotenv(dotenv_path=env_path)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://localhost:5432/satyaai_db")

engine = None
SessionLocal = None
Base = declarative_base()

try:
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=5,
        max_overflow=10,
        connect_args={"connect_timeout": 3},
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    logger.info("SQLAlchemy engine configured for PostgreSQL.")
except Exception as exc:
    logger.warning(f"Could not configure SQLAlchemy engine: {exc}")


def get_db() -> Generator:
    """FastAPI dependency for database sessions with automatic cleanup."""
    if SessionLocal is None:
        raise RuntimeError("Database engine is not initialized.")
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def check_connection() -> bool:
    """Check if PostgreSQL database is reachable and accepting queries."""
    if engine is None:
        return False
    try:
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return True
    except Exception as exc:
        logger.debug(f"Database connection check failed: {exc}")
        return False


def init_db() -> bool:
    """Safely create tables on application startup. Fails gracefully if PostgreSQL is offline."""
    if engine is None:
        logger.warning("Database engine is not configured; skipping table creation.")
        return False
    try:
        from backend.database.models import Analysis  # ensure models are registered
        Base.metadata.create_all(bind=engine)
        logger.info("PostgreSQL database tables verified and ready in satyaai_db.")
        return True
    except Exception as exc:
        logger.warning(
            f"PostgreSQL initialization failed: {exc}. SatyaAI will continue without database persistence."
        )
        return False
