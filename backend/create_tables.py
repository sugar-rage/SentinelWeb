"""Backward-compatible entry point that now applies Alembic migrations."""

from pathlib import Path

from alembic import command
from alembic.config import Config

backend_dir = Path(__file__).resolve().parent
config = Config(str(backend_dir / "alembic.ini"))
config.set_main_option("script_location", str(backend_dir / "alembic"))
command.upgrade(config, "head")
print("Database migrations applied successfully.")
