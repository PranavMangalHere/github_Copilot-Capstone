"""Input validation utilities."""
import re
from typing import List, Tuple


def validate_email(email: str) -> Tuple[bool, str]:
    """Validate email format."""
    pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(pattern, email):
        return False, "Invalid email format"
    if len(email) > 255:
        return False, "Email too long"
    return True, ""


def validate_password(password: str) -> Tuple[bool, List[str]]:
    """Validate password complexity."""
    errors = []
    if len(password) < 8:
        errors.append("Minimum 8 characters required")
    if not re.search(r"[A-Z]", password):
        errors.append("At least one uppercase letter required")
    if not re.search(r"[a-z]", password):
        errors.append("At least one lowercase letter required")
    if not re.search(r"[0-9]", password):
        errors.append("At least one digit required")
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        errors.append("At least one special character required")
    return len(errors) == 0, errors
