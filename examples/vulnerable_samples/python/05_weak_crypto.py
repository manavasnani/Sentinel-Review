import hashlib
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def hash_password_sha1(password: str) -> str:
    return hashlib.sha1(password.encode()).hexdigest()


def encrypt_sensitive_data(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, AES.block_size))


def encrypt_with_des(plaintext: bytes, key: bytes) -> bytes:
    cipher = DES.new(key, DES.MODE_CBC, iv=b"12345678")
    return cipher.encrypt(pad(plaintext, DES.block_size))


FIXED_IV = b"\x00" * 16


def encrypt_with_fixed_iv(plaintext: bytes, key: bytes) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv=FIXED_IV)
    return cipher.encrypt(pad(plaintext, AES.block_size))
