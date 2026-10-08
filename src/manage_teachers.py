import argparse
import getpass
import json
import os
import re

from src.teacher_auth import (
    TEACHERS_FILE,
    create_password_record,
    load_teacher_records,
)


def main():
    parser = argparse.ArgumentParser(description="Add a teacher sign-in.")
    parser.add_argument("username", help="Assigned teacher username")
    args = parser.parse_args()

    username = args.username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", username):
        parser.error("username must be 1-64 letters, numbers, dots, underscores, or hyphens")

    if not TEACHERS_FILE.exists():
        TEACHERS_FILE.write_text('{"teachers": {}}\n', encoding="utf-8")
        os.chmod(TEACHERS_FILE, 0o600)

    teachers = load_teacher_records(TEACHERS_FILE)
    if username in teachers:
        parser.error(f"teacher {username!r} already exists")

    password = getpass.getpass("Assigned password: ")
    if len(password) < 12:
        parser.error("password must be at least 12 characters")
    if password != getpass.getpass("Confirm password: "):
        parser.error("passwords do not match")

    teachers[username] = create_password_record(password)
    temporary_file = TEACHERS_FILE.with_suffix(".json.tmp")
    temporary_file.write_text(
        json.dumps({"teachers": teachers}, indent=2) + "\n", encoding="utf-8"
    )
    os.chmod(temporary_file, 0o600)
    temporary_file.replace(TEACHERS_FILE)
    print(f"Added teacher {username!r} to {TEACHERS_FILE}.")


if __name__ == "__main__":
    main()
