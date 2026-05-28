"""
Clean sample: correct password hashing.

This file SHOULD produce ZERO findings. bcrypt, argon2, scrypt, and PBKDF2
with appropriate parameters are explicitly listed as safe in the system
prompt. Flagging any of these is a false positive.
"""

import bcrypt
from argon2 import PasswordHasher
import hashlib
import secrets


def hash_password_bcrypt(password: str) -> bytes:
    """Safe: bcrypt with a generated salt, default work factor."""
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def verify_password_bcrypt(password: str, stored_hash: bytes) -> bool:
    """Safe: bcrypt verification."""
    return bcrypt.checkpw(password.encode(), stored_hash)


def hash_password_argon2(password: str) -> str:
    """Safe: argon2 is the current best-in-class password hash."""
    hasher = PasswordHasher()
    return hasher.hash(password)


def hash_password_pbkdf2(password: str, salt: bytes) -> bytes:
    """Safe: PBKDF2 with SHA-256 and 600,000 iterations (OWASP 2023 guidance)."""
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode(),
        salt,
        iterations=600_000,
    )


def generate_token() -> str:
    """Safe: secrets module is the right choice for cryptographic tokens."""
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    """Safe: secrets.token_hex for session IDs."""
    return secrets.token_hex(16)
