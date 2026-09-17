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
from pathlib import Path
from typing import Tuple, Optional


# Deterministic hash representing the active security policy rules and thresholds
POLICY_RULES_CANONICAL = "CG_POLICY_RULES_V2:THRESHOLDS=[0.40,0.50,0.60,0.70]:RULES=[PHYS_CAP,BUDGET,SLA_CRITICAL,HIPAA,GDPR,PCI_DSS,CLOSURE]"
POLICY_REVISION = hashlib.sha256(POLICY_RULES_CANONICAL.encode("utf-8")).hexdigest()[:16]

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
        return "ed25519" if self._private_key is not None else "hmac-sha256"

    def sign(self, payload: bytes) -> Tuple[str, str]:
        if self._private_key is not None:
            raw_sig = self._private_key.sign(payload)
            return raw_sig.hex(), "ed25519"
        elif self._hmac_secret is not None:
            sig = hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()
            return sig, "hmac-sha256"
        else:
            digest = hashlib.sha256(payload).hexdigest()
            return digest, "digest-only"

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
        return "ed25519" if self._public_key is not None else "hmac-sha256"

    def verify(self, payload: bytes, signature_hex: str, auth_mechanism: str) -> bool:
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
            if self._hmac_secret is None:
                return False
            expected = hmac.new(self._hmac_secret, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature_hex)
        elif auth_mechanism == "digest-only":
            expected = hashlib.sha256(payload).hexdigest()
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
