"""
Project 1: Cryptography Algorithms Implementation
Core cryptographic engine supporting SHA-256, AES-256 (with HMAC-SHA256), and RSA-2048.
"""

import base64
import hashlib
import hmac
import secrets
from typing import Dict, Tuple

import pyaes
import rsa

def sha256_hash(data: str) -> str:
    """Compute the hexadecimal SHA-256 digest of a UTF-8 string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_sha256(data: str, expected_digest: str) -> bool:
    """Verify data integrity against an expected SHA-256 hex digest."""
    computed = sha256_hash(data)
    return hmac.compare_digest(computed, expected_digest.strip().lower())



def generate_aes_key() -> bytes:
    """Generate a cryptographically secure 256-bit (32-byte) AES key."""
    return secrets.token_bytes(32)


def aes_encrypt(plaintext: str, key: bytes) -> Dict[str, str]:
    """
    Encrypt UTF-8 plaintext using AES-256 in CTR mode with an HMAC-SHA256 tag
    (Encrypt-then-MAC) for confidentiality and tamper detection.
    """
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte (64 hex character) key.")

    iv_bytes = secrets.token_bytes(16)
    iv_int = int.from_bytes(iv_bytes, byteorder="big")

    aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(iv_int))
    ciphertext = aes.encrypt(plaintext.encode("utf-8"))

    # Derive a separate MAC key from the master key and authenticate IV + ciphertext
    mac_key = hashlib.sha256(key + b"mac").digest()
    tag = hmac.new(mac_key, iv_bytes + ciphertext, hashlib.sha256).digest()

    return {
        "key_hex": key.hex(),
        "iv_b64": base64.b64encode(iv_bytes).decode("utf-8"),
        "ciphertext_b64": base64.b64encode(ciphertext).decode("utf-8"),
        "tag_b64": base64.b64encode(tag).decode("utf-8"),
    }


def aes_decrypt(ciphertext_b64: str, iv_b64: str, tag_b64: str, key: bytes) -> str:
    """Verify the HMAC-SHA256 authentication tag and decrypt AES-256-CTR ciphertext."""
    if len(key) != 32:
        raise ValueError("AES-256 requires a 32-byte (64 hex character) key.")

    iv_bytes = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    provided_tag = base64.b64decode(tag_b64)

    mac_key = hashlib.sha256(key + b"mac").digest()
    expected_tag = hmac.new(mac_key, iv_bytes + ciphertext, hashlib.sha256).digest()

    if not hmac.compare_digest(expected_tag, provided_tag):
        raise ValueError("Authentication failed: ciphertext, IV, key, or tag was tampered with.")

    iv_int = int.from_bytes(iv_bytes, byteorder="big")
    aes = pyaes.AESModeOfOperationCTR(key, counter=pyaes.Counter(iv_int))
    plaintext_bytes = aes.decrypt(ciphertext)
    return plaintext_bytes.decode("utf-8")


# ==========================================
# 3. RSA-2048 Asymmetric Encryption
# ==========================================

def generate_rsa_keypair(key_size: int = 2048) -> Tuple[rsa.PublicKey, rsa.PrivateKey]:
    """Generate an RSA public/private key pair (default: 2048 bits)."""
    return rsa.newkeys(key_size)


def export_rsa_keys_pem(
    public_key: rsa.PublicKey, private_key: rsa.PrivateKey
) -> Tuple[str, str]:
    """Export RSA keys as PEM-formatted strings."""
    pub_pem = public_key.save_pkcs1(format="PEM").decode("utf-8")
    priv_pem = private_key.save_pkcs1(format="PEM").decode("utf-8")
    return pub_pem, priv_pem


def rsa_encrypt(plaintext: str, public_key: rsa.PublicKey) -> str:
    """Encrypt a short UTF-8 message with an RSA public key and return Base64 ciphertext."""
    message_bytes = plaintext.encode("utf-8")
    max_bytes = (public_key.n.bit_length() // 8) - 11  # PKCS#1 v1.5 padding overhead
    if len(message_bytes) > max_bytes:
        raise ValueError(
            f"Message too long for RSA key size ({len(message_bytes)} bytes; max {max_bytes} bytes)."
        )

    ciphertext = rsa.encrypt(message_bytes, public_key)
    return base64.b64encode(ciphertext).decode("utf-8")


def rsa_decrypt(ciphertext_b64: str, private_key: rsa.PrivateKey) -> str:
    """Decrypt Base64 RSA ciphertext using the matching private key."""
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext_bytes = rsa.decrypt(ciphertext, private_key)
    return plaintext_bytes.decode("utf-8")