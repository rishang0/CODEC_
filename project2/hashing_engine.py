"""
Project 2: Password Hashing, Cracking Simulation & Security Auditor
Core security engine using Python's built-in cryptographic and standard libraries.
"""

import hashlib
import hmac
import math
import secrets
import string
import time
from typing import Dict, List, Optional, Tuple

COMMON_PASSWORDS: List[str] = [
    "123456",
    "password",
    "123456789",
    "12345678",
    "qwerty",
    "abc123",
    "password1",
    "admin",
    "admin123",
    "letmein",
    "welcome",
    "monkey",
    "dragon",
    "football",
    "iloveyou",
    "sunshine",
    "princess",
    "passw0rd",
    "p@ssword",
    "india123",
    "lucknow123",
    "qwerty123",
    "root",
    "toor",
    "test1234",
]


# ==========================================
# 1. Unsalted Hashing & Dictionary Attack Demo
# ==========================================

def unsalted_hash(password: str, algorithm: str = "sha256") -> str:
    """Compute a fast, unsalted hash (MD5 or SHA-256) to demonstrate vulnerability."""
    algo = algorithm.lower()
    if algo not in ("md5", "sha256"):
        raise ValueError("Supported unsalted algorithms: 'md5', 'sha256'.")
    return hashlib.new(algo, password.encode("utf-8")).hexdigest()


def simulate_dictionary_attack(
    target_hash: str, algorithm: str = "sha256", wordlist: Optional[List[str]] = None
) -> Dict[str, object]:
    """
    Simulate an offline dictionary attack against an unsalted hash using a local wordlist.
    Returns whether the password was cracked, attempts made, and elapsed time.
    """
    candidates = wordlist if wordlist is not None else COMMON_PASSWORDS
    target = target_hash.strip().lower()
    start = time.perf_counter()

    for idx, word in enumerate(candidates, start=1):
        if unsalted_hash(word, algorithm) == target:
            elapsed_ms = (time.perf_counter() - start) * 1000
            return {
                "cracked": True,
                "password": word,
                "attempts": idx,
                "elapsed_ms": elapsed_ms,
            }

    elapsed_ms = (time.perf_counter() - start) * 1000
    return {
        "cracked": False,
        "password": None,
        "attempts": len(candidates),
        "elapsed_ms": elapsed_ms,
    }


# ==========================================
# 2. Salted SHA-256 Hashing
# ==========================================

def salted_sha256_hash(password: str, salt: Optional[bytes] = None) -> Tuple[str, str]:
    """Generate a 16-byte random salt (if omitted) and compute SHA-256(salt || password)."""
    salt_bytes = salt if salt is not None else secrets.token_bytes(16)
    digest = hashlib.sha256(salt_bytes + password.encode("utf-8")).hexdigest()
    return salt_bytes.hex(), digest


def verify_salted_sha256(password: str, salt_hex: str, stored_digest: str) -> bool:
    """Verify a password against a stored salt and SHA-256 digest in constant time."""
    salt_bytes = bytes.fromhex(salt_hex)
    _, computed_digest = salted_sha256_hash(password, salt=salt_bytes)
    return hmac.compare_digest(computed_digest, stored_digest.strip().lower())


# ==========================================
# 3. Adaptive Key Stretching (PBKDF2-HMAC-SHA256)
# ==========================================

def pbkdf2_hash(
    password: str, iterations: int = 600_000, salt: Optional[bytes] = None
) -> Dict[str, object]:
    """
    Derive a secure password hash using PBKDF2-HMAC-SHA256.
    600,000 iterations aligns with OWASP recommendations for SHA-256.
    """
    salt_bytes = salt if salt is not None else secrets.token_bytes(16)
    start = time.perf_counter()
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations, dklen=32)
    elapsed_ms = (time.perf_counter() - start) * 1000

    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt_hex": salt_bytes.hex(),
        "hash_hex": dk.hex(),
        "elapsed_ms": elapsed_ms,
    }


def verify_pbkdf2(
    password: str, salt_hex: str, stored_hash_hex: str, iterations: int
) -> bool:
    """Verify a password against a stored PBKDF2-HMAC-SHA256 record."""
    salt_bytes = bytes.fromhex(salt_hex)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations, dklen=32)
    return hmac.compare_digest(dk.hex(), stored_hash_hex.strip().lower())


def benchmark_hashing(password: str, iterations: int = 600_000) -> Dict[str, float]:
    """Compare execution time of raw SHA-256 vs. PBKDF2-HMAC-SHA256."""
    start_fast = time.perf_counter()
    unsalted_hash(password, "sha256")
    fast_ms = (time.perf_counter() - start_fast) * 1000

    pbkdf2_result = pbkdf2_hash(password, iterations=iterations)
    slow_ms = float(pbkdf2_result["elapsed_ms"])
    slowdown = slow_ms / fast_ms if fast_ms > 0 else 0.0

    return {
        "sha256_ms": fast_ms,
        "pbkdf2_ms": slow_ms,
        "slowdown_factor": slowdown,
    }


# ==========================================
# 4. Password Entropy & Resilience Auditor
# ==========================================

def _format_duration(seconds: float) -> str:
    """Convert raw seconds into a human-readable time duration."""
    if seconds < 1e-3:
        return "Instant (< 1 millisecond)"
    if seconds < 1:
        return f"{seconds * 1000:.2f} milliseconds"
    if seconds < 60:
        return f"{seconds:.2f} seconds"
    if seconds < 3600:
        return f"{seconds / 60:.2f} minutes"
    if seconds < 86400:
        return f"{seconds / 3600:.2f} hours"
    if seconds < 31_536_000:
        return f"{seconds / 86400:.2f} days"
    years = seconds / 31_536_000
    if years < 1e6:
        return f"{years:,.1f} years"
    if years < 1e9:
        return f"{years / 1e6:,.2f} million years"
    return f"{years / 1e9:,.2f} billion+ years"


def audit_password(password: str) -> Dict[str, object]:
    """
    Evaluate password character diversity, combinatorial entropy (bits),
    estimated offline GPU brute-force crack times, and remediation recommendations.
    """
    length = len(password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    entropy_bits = length * math.log2(pool_size) if (length > 0 and pool_size > 0) else 0.0
    in_common_list = password.lower() in COMMON_PASSWORDS

    # Average guesses needed = 2^(entropy - 1)
    # Offline GPU attack rates:
    # - Fast unsalted SHA-256: ~10 billion guesses/sec (1e10)
    # - PBKDF2-HMAC-SHA256 (600k iterations): ~10,000 guesses/sec (1e4)
    if entropy_bits == 0 or in_common_list:
        crack_fast_str = "Instant (found in common breached password lists)"
        crack_pbkdf2_str = "Seconds to minutes (dictionary match)"
    else:
        log2_avg_guesses = max(entropy_bits - 1.0, 0.0)
        if log2_avg_guesses > 120:
            crack_fast_str = "Trillions+ years (computationally infeasible)"
            crack_pbkdf2_str = "Trillions+ years (computationally infeasible)"
        else:
            avg_guesses = 2 ** log2_avg_guesses
            crack_fast_str = _format_duration(avg_guesses / 1e10)
            crack_pbkdf2_str = _format_duration(avg_guesses / 1e4)

    # Rating classification
    if in_common_list or entropy_bits < 36:
        rating = "CRITICAL / VERY WEAK"
    elif entropy_bits < 50:
        rating = "WEAK"
    elif entropy_bits < 65:
        rating = "MODERATE"
    elif entropy_bits < 80:
        rating = "STRONG"
    else:
        rating = "VERY STRONG"

    # Actionable remediation guidance
    advice: List[str] = []
    if in_common_list:
        advice.append("Immediately replace: this password appears in common breach wordlists.")
    if length < 12:
        advice.append("Increase length to at least 12-16 characters (length boosts entropy fastest).")
    if not has_upper:
        advice.append("Add uppercase letters (A-Z) to expand the character pool.")
    if not has_lower:
        advice.append("Add lowercase letters (a-z) to expand the character pool.")
    if not has_digit:
        advice.append("Include numeric digits (0-9).")
    if not has_symbol:
        advice.append("Include special symbols (e.g., !@#$%^&*) or use a 4+ word random passphrase.")
    if not advice:
        advice.append("Good resilience. Store with a password manager and enable MFA where supported.")

    return {
        "length": length,
        "pool_size": pool_size,
        "entropy_bits": round(entropy_bits, 2),
        "rating": rating,
        "in_common_list": in_common_list,
        "crack_time_unsalted_sha256": crack_fast_str,
        "crack_time_pbkdf2_600k": crack_pbkdf2_str,
        "remediation": advice,
    }