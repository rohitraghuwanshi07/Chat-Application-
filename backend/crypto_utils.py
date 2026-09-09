"""
crypto_utils.py
----------------
Two unrelated jobs:
  1. SIGNING (Ed25519) -- proves WHO sent a message and that it hasn't
     changed since. Each user has a private/public key pair.
  2. ENCRYPTION AT REST (Fernet/AES) -- hides message content in the
     database. One shared key across the whole cluster is enough,
     since we're not proving who encrypted it, just hiding it.
"""

import base64
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken


# =================================================================
# 1. SIGNING
# =================================================================

def generate_signing_keypair():
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def pem_to_public_key(pem_str: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def private_key_to_pem(private_key: Ed25519PrivateKey) -> str:
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")


def pem_to_private_key(pem_str: str) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(pem_str.encode("utf-8"), password=None)


def sign_text(private_key: Ed25519PrivateKey, plaintext: str) -> str:
    signature = private_key.sign(plaintext.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(public_key: Optional[Ed25519PublicKey], plaintext: str, signature_b64: str) -> bool:
    if not signature_b64 or public_key is None:
        return False
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, plaintext.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


# =================================================================
# 2. ENCRYPTION AT REST
# =================================================================
# NOTE: the old load_or_create_encryption_key() (local file) is gone.
# The Fernet key now lives in the shared DB via
# database.get_or_create_fernet_key(), so every backend node uses the
# same one. See server.py's on_startup.

def encrypt_text(fernet: Fernet, plaintext: str) -> str:
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(fernet: Fernet, ciphertext: str) -> Optional[str]:
    try:
        return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None