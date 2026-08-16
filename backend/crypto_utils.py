"""
crypto_utils.py
----------------
Every cryptographic operation the app needs lives here, split into two
UNRELATED jobs that beginners often mix up:

  1. SIGNING (asymmetric, Ed25519)
     Proves WHO sent a message and that the text hasn't changed since
     they sent it. Each user gets their own private/public key PAIR.
     Private key -> signs. Public key -> verifies. This is what
     requirements 5 and 6 ("signing key pair", "signature verified")
     are asking for.

  2. ENCRYPTION AT REST (symmetric, Fernet/AES)
     Makes sure that if someone opens chat.db directly, they see
     scrambled bytes, not readable text. This is what requirement 3
     ("messages are not stored as plaintext") is asking for.
     One shared key is enough here, because we're just protecting a
     file on disk -- we're not trying to prove who encrypted it.

Signing != encryption. Signing does NOT hide content (anyone can still
read a signed-but-unencrypted message). Encryption does NOT prove who
wrote something (anyone with the key can encrypt anything). You need
BOTH to satisfy every requirement.
"""

import base64
import os
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from cryptography.fernet import Fernet, InvalidToken


# =================================================================
# 1. SIGNING -- proves identity + catches tampering
# =================================================================

def generate_signing_keypair():
    """Makes a brand-new Ed25519 key pair for a user who's never been
    seen before. Returns (private_key, public_key)."""
    private_key = Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    """Converts a public key object into plain text (PEM format) so it
    can be stored in a normal SQLite TEXT column."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def pem_to_public_key(pem_str: str) -> Ed25519PublicKey:
    """The reverse of public_key_to_pem -- text back into a usable key object."""
    return serialization.load_pem_public_key(pem_str.encode("utf-8"))


def sign_text(private_key: Ed25519PrivateKey, plaintext: str) -> str:
    """Signs the EXACT plaintext string. Returns a base64 signature,
    safe to store as text."""
    signature = private_key.sign(plaintext.encode("utf-8"))
    return base64.b64encode(signature).decode("ascii")


def verify_signature(public_key: Optional[Ed25519PublicKey], plaintext: str, signature_b64: str) -> bool:
    """
    Returns True ONLY IF `signature_b64` is a valid signature of THIS
    EXACT `plaintext`, made by the matching private key.

    If even one character of plaintext has changed since it was signed,
    this returns False. That single fact is the entire tamper-detection
    mechanism (requirement 4) -- there's no separate "tamper checker",
    it's just this function being re-run on stored data.

    Never raises: garbage/missing signatures just fail, they don't crash.
    """
    if not signature_b64 or public_key is None:
        return False
    try:
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, plaintext.encode("utf-8"))
        return True
    except (InvalidSignature, ValueError):
        return False


# =================================================================
# 2. ENCRYPTION AT REST -- hides content in the database
# =================================================================

KEY_FILE = "server_secret.key"


def load_or_create_encryption_key() -> bytes:
    """
    Loads the server's symmetric encryption key from a local file,
    generating one the first time the server ever runs.

    IMPORTANT: server_secret.key must NEVER be committed to git (see
    .gitignore). Anyone who has this file AND chat.db can read every
    message. Keeping it out of version control is what makes
    "encrypted at rest" actually mean something.
    """
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, "rb") as f:
            return f.read()

    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as f:
        f.write(key)
    return key


def encrypt_text(fernet: Fernet, plaintext: str) -> str:
    """Plaintext -> ciphertext string, ready to store in SQLite."""
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_text(fernet: Fernet, ciphertext: str) -> Optional[str]:
    """
    Ciphertext -> plaintext. Returns None if the ciphertext has been
    corrupted or tampered with -- Fernet has its OWN built-in integrity
    check (separate from our Ed25519 signature), so a directly-edited
    database row will usually fail right here, before we even get to
    check the signature.
    """
    try:
        return fernet.decrypt(ciphertext.encode("ascii")).decode("utf-8")
    except InvalidToken:
        return None
