"""
X25519 key exchange with commit-reveal and SAS verification.

Protocol:
  A → B:  commitment = SHA-256(pk_a || random_a)     (32 bytes)
  B → A:  pk_b                                        (32 bytes)
  A → B:  pk_a || random_a                            (48 bytes)
  Both:   verify commitment, derive shared secret, display SAS
"""

import os
import hashlib

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from .errors import CommitmentMismatchError

_PK_SIZE = 32
_RANDOM_SIZE = 16
_SAS_DIGITS = 6
COMMITMENT_SIZE = 32
PUBLIC_KEY_SIZE = 32
REVEAL_SIZE = _PK_SIZE + _RANDOM_SIZE

class Initiator:
    """Device A - starts the key exchange."""

    def __init__(self):
        self._sk = X25519PrivateKey.generate()
        self._random = os.urandom(_RANDOM_SIZE)
        self._pk_bytes = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        self._session_key: bytes | None = None
        self._sas: str | None = None

    def get_commitment(self) -> bytes:
        """Step 1: Generate commitment to send to responder."""
        return hashlib.sha256(self._pk_bytes + self._random).digest()
    
    def receive_public_key_and_reveal(self, pk_b_bytes: bytes) -> bytes:
        """
        Step 3: Receive responder's public key, compute shared secret,
        and return the reveal (pk_a || random_a) to send back.
        """
        pk_b = X25519PublicKey.from_public_bytes(pk_b_bytes)
        shared = self._sk.exchange(pk_b)

        self._session_key = _derive_session_key(
            shared, self._pk_bytes, pk_b_bytes
        )
        self._sas = _derive_sas(shared)

        return self._pk_bytes + self._random
    
    @property
    def session_key(self) -> bytes:
        assert self._session_key is not None, "Handshake not complete"
        return self._session_key
    
    @property
    def sas(self) -> str:
        assert self._sas is not None, "Handshake not complete"
        return self._sas

class Responder:
    """Device B - responds to the key exchange."""

    def __init__(self):
        self._sk = X25519PrivateKey.generate()
        self._pk_bytes = self._sk.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw
        )
        self._commitment: bytes | None = None
        self._session_key: bytes | None = None
        self._sas: str | None = None

    def receive_commitment(self, commitment: bytes) -> bytes:
        """
        Step 2: Receive and store commitment from initiator.
        Returns our public key to send back.
        """
        self._commitment = commitment
        return self._pk_bytes
    
    def receive_reveal(self, reveal: bytes) -> None:
        """
        Step 4: Receive reveal (pk_a || random_a), verify commitment,
        and derive session key + SAS.

        Raises:
            CommitmentMismatchError: if commitment doesn't match reveal.
        """
        assert self._commitment is not None, "No commitment received"

        pk_a_bytes = reveal[:_PK_SIZE]
        random_a = reveal[_PK_SIZE:]

        # Verify the commitment before trusting pk_a
        expected = hashlib.sha256(pk_a_bytes + random_a).digest()
        if expected != self._commitment:
            raise CommitmentMismatchError(
                "Commitment does not match reveal - possible MITM"
            )
        
        pk_a = X25519PublicKey.from_public_bytes(pk_a_bytes)
        shared = self._sk.exchange(pk_a)

        self._session_key = _derive_session_key(
            shared, pk_a_bytes, self._pk_bytes
        )
        self._sas = _derive_sas(shared)

    @property
    def session_key(self) -> bytes:
        assert self._session_key is not None, "Handshake not complete"
        return self._session_key
    
    @property
    def sas(self) -> str:
        assert self._sas is not None, "Handshake not complete"
        return self._sas
    
def _derive_session_key(
        shared_secret: bytes, pk_a: bytes, pk_b: bytes) -> bytes:
    """Derive AES-256 session key from DH shared secret."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=pk_a + pk_b,
        info=b"ggwave_aes256gcm-session-v1",
    ).derive(shared_secret)

def _derive_sas(shared_secret: bytes) -> str:
    """Derive a human-readable Short Authentication String."""
    sas_bytes = HKDF(
        algorithm=hashes.SHA256(),
        length=4,
        salt=None,
        info=b"ggwave-sas-v1",
    ).derive(shared_secret)
    num = int.from_bytes(sas_bytes, "big") % (10**_SAS_DIGITS)
    return f"{num:0{_SAS_DIGITS}d}"