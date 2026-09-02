"""One-time, local-only initial administrator provisioning command."""

import argparse
import getpass
import secrets
import sys
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))

from app.auth.password import hash_password  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.database.database import SessionLocal  # noqa: E402
from app.database.models.administrator import Administrator  # noqa: E402
from app.schemas.auth import UserRegister  # noqa: E402
from app.services.security_audit_service import add_security_event  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="Provision the first SentinelWeb administrator")
    parser.add_argument("--username", required=True)
    parser.add_argument("--email", required=True)
    args = parser.parse_args()

    configured_secret = settings.ADMIN_BOOTSTRAP_SECRET
    if len(configured_secret) < 32:
        print("ADMIN_BOOTSTRAP_SECRET must be configured with at least 32 characters.", file=sys.stderr)
        return 2
    supplied_secret = getpass.getpass("Bootstrap secret: ")
    if not secrets.compare_digest(configured_secret, supplied_secret):
        print("Invalid bootstrap secret.", file=sys.stderr)
        return 3

    password = getpass.getpass("New admin password: ")
    confirmation = getpass.getpass("Confirm admin password: ")
    if not secrets.compare_digest(password, confirmation):
        print("Passwords do not match.", file=sys.stderr)
        return 4

    validated = UserRegister(username=args.username, email=args.email, password=password)
    db = SessionLocal()
    try:
        if db.query(Administrator).filter(Administrator.role == "admin").first():
            print("An administrator already exists; bootstrap is disabled.", file=sys.stderr)
            return 5
        admin = Administrator(
            username=validated.username,
            email=validated.email,
            password_hash=hash_password(validated.password),
            role="admin",
        )
        db.add(admin)
        db.flush()
        add_security_event(
            db,
            event_type="admin_bootstrap",
            outcome="success",
            user_id=admin.id,
            details={"role": "admin", "method": "local_cli"},
        )
        db.commit()
        print(f"Administrator '{admin.username}' created successfully.")
        return 0
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
