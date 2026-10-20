"""Create or update a teacher login in the local JSON credential store."""

import getpass
import hashlib
import json
import os
import secrets
import sys
from pathlib import Path


ITERATIONS = 310_000
TEACHERS_FILE = Path(os.environ.get("TEACHERS_FILE", Path(__file__).with_name("teachers.json")))


def make_password_hash(password):
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), ITERATIONS
    ).hex()
    return f"pbkdf2_sha256${ITERATIONS}${salt}${digest}"


def main():
    if len(sys.argv) != 2 or not sys.argv[1].strip():
        print("Usage: python src/manage_teachers.py <username>", file=sys.stderr)
        return 2

    username = sys.argv[1].strip()
    password = getpass.getpass("Assigned teacher password: ")
    if not password:
        print("Password must not be empty.", file=sys.stderr)
        return 2

    try:
        data = json.loads(TEACHERS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        data = {"teachers": []}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Could not read teacher accounts: {exc}", file=sys.stderr)
        return 1

    teachers = data.get("teachers", [])
    account = next((item for item in teachers if item.get("username") == username), None)
    if account is None:
        teachers.append({"username": username, "password_hash": make_password_hash(password)})
    else:
        account["password_hash"] = make_password_hash(password)

    TEACHERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    temporary_file = TEACHERS_FILE.with_suffix(".json.tmp")
    temporary_file.write_text(
        json.dumps({"teachers": teachers}, indent=2) + "\n", encoding="utf-8"
    )
    os.replace(temporary_file, TEACHERS_FILE)
    try:
        TEACHERS_FILE.chmod(0o600)
    except OSError:
        pass

    print(f"Teacher account '{username}' saved to {TEACHERS_FILE}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())