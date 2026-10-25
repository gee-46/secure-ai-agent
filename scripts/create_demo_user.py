"""Create a demo user account with a freshly generated random password.

This script NEVER uses a hardcoded password. It generates a random,
strong password at run time, prints it ONCE to the terminal, and does not
persist it anywhere in plaintext. Use this only for local demonstration
purposes.

Usage: python scripts/create_demo_user.py [username]
"""
import secrets
import string
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.auth.auth_service import register_user
from src.storage.db import initialize_database
from src.utils.validation import ValidationError


def generate_strong_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (
            any(c.islower() for c in pwd)
            and any(c.isupper() for c in pwd)
            and any(c.isdigit() for c in pwd)
            and any(c in "!@#$%^&*" for c in pwd)
        ):
            return pwd


def main() -> None:
    username = sys.argv[1] if len(sys.argv) > 1 else "demo_user"
    initialize_database()
    password = generate_strong_password()
    try:
        user = register_user(username, password)
    except ValidationError as exc:
        print(f"Could not create demo user: {exc}")
        print("If the account already exists, log in with its original password, "
              "or choose a different demo username.")
        return

    print("=" * 60)
    print(" DEMO ACCOUNT CREATED (for local demonstration only)")
    print("=" * 60)
    print(f" Username: {user.username}")
    print(f" Password: {password}")
    print("=" * 60)
    print(" This password is shown ONCE and is not stored anywhere in")
    print(" plaintext. Save it now if you intend to use this account.")
    print(" Do not reuse this password for any real account.")


if __name__ == "__main__":
    main()
