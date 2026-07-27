"""
Vulnerable sample: Cryptographic failures.

Expected findings:
    - CWE-327 (Use of Broken Cryptographic Algorithm) - MD5 for passwords at line 23
    - CWE-327 (Weak Block Cipher Mode) - AES-ECB at line 36
    - CWE-326 (Inadequate Encryption Strength) - DES at line 47
    - Severity: high
    - Confidence: high

DO NOT use any pattern in this file in production code.
"""

import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad


def hash_password(password: str) -> str:
    """Hash a password. VULNERABLE: MD5 is unsuitable for password hashing."""
    # MD5 is fast, unsalted here, and broken for password storage
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    """Also vulnerable: SHA-1 is similarly unsuitable for passwords."""
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_sensitive_data(plaintext: bytes, key: bytes) -> bytes:
    """Encrypt user data. VULNERABLE: ECB mode leaks plaintext patterns."""
    # ECB encrypts identical blocks to identical ciphertext (no IV, no diffusion)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def encrypt_with_des(plaintext: bytes, key: bytes) -> bytes:
    """VULNERABLE: DES has a 56-bit key, brute-forceable in hours."""
    cipher = DES.new(key, DES.MODE_CBC, iv=b"12345678")
    return cipher.encrypt(pad(plaintext, DES.block_size))


# Hardcoded IV - another crypto antipattern (predictable IVs)
FIXED_IV = b"\x00" * 16


def encrypt_with_fixed_iv(plaintext: bytes, key: bytes) -> bytes:
    """VULNERABLE: reusing a fixed IV in CBC defeats semantic security."""
    cipher = AES.new(key, AES.MODE_CBC, iv=FIXED_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))
