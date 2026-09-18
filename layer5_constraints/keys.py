"""
=============================================================================
LAYER 5: ASYMMETRIC KEY MANAGEMENT & ROLE-SEPARATED CERTIFICATE SIGNING
Module: keys.py
-----------------------------------------------------------------------------
Problem Solved:
  Implements role-separated cryptographic signing and verification for
  Pre-Solve Safety Certificates and State-Envelope Certificates.
  
  Role Separation Architecture:
    - Certifier Role: Holds the private signing key (CertifierKey).
      Only PreSolveSafetyCertifier signs certificates.
    - Compiler & Actuator Verifier Role: Holds only the public verification key
      (VerifierKey). FormulationCompiler and ActuationCapabilityVerifier verify
      signatures without having access to private signing material.
  
  Primary mechanism: Ed25519 asymmetric digital signatures (RFC 8032).
  Fallback mechanism: HMAC-SHA256 (clearly flagged as "hmac-sha256").
=============================================================================
"""

import hmac
import hashlib
import os
import logging
from pathlib import Path
from typing import Tuple, Optional, Set

logger = logging.getLogger(__name__)

# Cryptographic configuration
ALLOW_HMAC_FALLBACK: bool = os.environ.get("ALLOW_HMAC_FALLBACK", "false").lower() in ("true", "1")


class CryptographicConfigurationError(RuntimeError):
    """Raised when an unapproved or unavailable cryptographic mechanism is configured."""
    pass


def get_approved_auth_mechanisms() -> Set[str]:
    """
    Returns the set of approved signature authentication mechanisms.
    Default: {"ed25519"}. HMAC is permitted only if ALLOW_HMAC_FALLBACK is True.
    """
    approved = {"ed25519"}
    if ALLOW_HMAC_FALLBACK:
        approved.add("hmac-sha256")
    return approved


try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


KEYS_DIR = Path(__file__).resolve().parent.parent / ".keys"
PRIVATE_KEY_PATH = KEYS_DIR / "certifier_ed25519.key"
PUBLIC_KEY_PATH = KEYS_DIR / "certifier_ed25519.pub"
HMAC_SECRET_PATH = KEYS_DIR / "certifier_hmac.secret"


class CertifierKey:
    """
    Private signing key held exclusively by the Certifier role.
    """
    def __init__(self, private_key=None, hmac_secret: Optional[bytes] = None):
        self._private_key = private_key
        self._hmac_secret = hmac_secret

    @property
    def mechanism(self) -> str:
        if self._private_key is not None:
            return "ed25519"
        elif ALLOW_HMAC_FALLBACK and self._hmac_secret is not None:
            return "hmac-sha256"
        raise CryptographicConfigurationError(
            "No approved signing mechanism available (cryptography library missing and ALLOW_HMAC_FALLBACK not enabled)."
        )

    def sign(self, payload: bytes) -> Tuple[str, str]:
        if self._private_key is not None:
            raw_sig = self._private_key.sign(payload)
            return raw_sig.hex(), "ed25519"
        elif ALLOW_HMAC_FALLBACK and self._hmac_secret is not None:
            logger.warning("Certifying with degraded HMAC-SHA256 fallback mechanism")
            sig = hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()
            return sig, "hmac-sha256"
        else:
            raise CryptographicConfigurationError(
                "Cannot sign certificate: Ed25519 key unavailable and ALLOW_HMAC_FALLBACK is not enabled."
            )

    def get_public_verifier(self) -> 'VerifierKey':
        if self._private_key is not None:
            return VerifierKey(public_key=self._private_key.public_key())
        return VerifierKey(hmac_secret=self._hmac_secret)


class VerifierKey:
    """
    Public verification key held by FormulationCompiler and Actuator verifiers.
    Possesses no signing capability.
    """
    def __init__(self, public_key=None, hmac_secret: Optional[bytes] = None):
        self._public_key = public_key
        self._hmac_secret = hmac_secret

    @property
    def mechanism(self) -> str:
        if self._public_key is not None:
            return "ed25519"
        elif ALLOW_HMAC_FALLBACK and self._hmac_secret is not None:
            return "hmac-sha256"
        return "unconfigured"

    def verify(self, payload: bytes, signature_hex: str, auth_mechanism: str) -> bool:
        if not signature_hex:
            return False
        approved = get_approved_auth_mechanisms()
        if auth_mechanism not in approved:
            return False

        if auth_mechanism == "ed25519":
            if self._public_key is None:
                return False
            try:
                sig_bytes = bytes.fromhex(signature_hex)
                self._public_key.verify(sig_bytes, payload)
                return True
            except Exception:
                return False
        elif auth_mechanism == "hmac-sha256":
            if not ALLOW_HMAC_FALLBACK or self._hmac_secret is None:
                return False
            logger.warning("Verifying certificate signature using degraded HMAC-SHA256 fallback")
            expected = hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        return False


_GLOBAL_CERTIFIER_KEY: Optional[CertifierKey] = None
_GLOBAL_VERIFIER_KEY: Optional[VerifierKey] = None


def init_keys() -> Tuple[CertifierKey, VerifierKey]:
    """
    Initializes or loads on-disk keys for development/runtime use.
    """
    global _GLOBAL_CERTIFIER_KEY, _GLOBAL_VERIFIER_KEY
    if _GLOBAL_CERTIFIER_KEY is not None and _GLOBAL_VERIFIER_KEY is not None:
        return _GLOBAL_CERTIFIER_KEY, _GLOBAL_VERIFIER_KEY

    KEYS_DIR.mkdir(parents=True, exist_ok=True)

    if HAS_CRYPTOGRAPHY:
        if PRIVATE_KEY_PATH.exists() and PUBLIC_KEY_PATH.exists():
            with open(PRIVATE_KEY_PATH, "rb") as f:
                priv = serialization.load_pem_private_key(f.read(), password=None)
            with open(PUBLIC_KEY_PATH, "rb") as f:
                pub = serialization.load_pem_public_key(f.read())
        else:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub = priv.public_key()
            with open(PRIVATE_KEY_PATH, "wb") as f:
                f.write(priv.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                ))
            with open(PUBLIC_KEY_PATH, "wb") as f:
                f.write(pub.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ))
        _GLOBAL_CERTIFIER_KEY = CertifierKey(private_key=priv)
        _GLOBAL_VERIFIER_KEY = VerifierKey(public_key=pub)
    else:
        if not ALLOW_HMAC_FALLBACK:
            raise CryptographicConfigurationError(
                "The 'cryptography' library is unavailable and ALLOW_HMAC_FALLBACK is not enabled. "
                "System refuses to silently downgrade to insecure mechanisms."
            )
        if HMAC_SECRET_PATH.exists():
            with open(HMAC_SECRET_PATH, "rb") as f:
                secret = f.read()
        else:
            secret = os.urandom(32)
            with open(HMAC_SECRET_PATH, "wb") as f:
                f.write(secret)
        _GLOBAL_CERTIFIER_KEY = CertifierKey(hmac_secret=secret)
        _GLOBAL_VERIFIER_KEY = VerifierKey(hmac_secret=secret)

    return _GLOBAL_CERTIFIER_KEY, _GLOBAL_VERIFIER_KEY


def get_certifier_key() -> CertifierKey:
    ck, _ = init_keys()
    return ck


def get_verifier_key() -> VerifierKey:
    _, vk = init_keys()
    return vk
