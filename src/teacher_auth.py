import hashlib
import hmac
import json
import os
import secrets
from pathlib import Path


PASSWORD_HASH_ITERATIONS = 310_000
TEACHERS_FILE = Path(
    os.environ.get("TEACHERS_FILE", Path(__file__).with_name("teachers.json"))
)


def create_password_record(password: str) -> dict[str, str]:
    salt = secrets.token_bytes(16)
    password_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_HASH_ITERATIONS
    )
    return {"salt": salt.hex(), "password_hash": password_hash.hex()}


def verify_password(password: str, record: dict[str, str]) -> bool:
    salt = bytes.fromhex(record["salt"])
    expected_hash = bytes.fromhex(record["password_hash"])
    actual_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt, PASSWORD_HASH_ITERATIONS
    )
    return hmac.compare_digest(actual_hash, expected_hash)


def load_teacher_records(path: Path) -> dict[str, dict[str, str]]:
    with path.open(encoding="utf-8") as teachers_file:
        data = json.load(teachers_file)
    teachers = data.get("teachers") if isinstance(data, dict) else None
    if not isinstance(teachers, dict):
        raise ValueError(f"Invalid teacher credential file: {path}")

    for username, record in teachers.items():
        if not isinstance(username, str) or not isinstance(record, dict):
            raise ValueError(f"Invalid teacher credential file: {path}")
        try:
            salt = bytes.fromhex(record["salt"])
            password_hash = bytes.fromhex(record["password_hash"])
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"Invalid teacher credential file: {path}") from error
        if len(salt) != 16 or len(password_hash) != 32:
            raise ValueError(f"Invalid teacher credential file: {path}")

    return teachers
