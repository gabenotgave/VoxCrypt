"""
AES-256-GCM authenticated encryption for short acoustic messages.

Wire format per frame:
  [version: 1B] [nonce: 12B] [ciphertext: NB] [tag: 16B]

The version byte is included as AAD (authenticated but not encrypted).
The tag is appended to ciphertext automatically by AESGCM.
"""

import os
import struct

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .errors import DecryptionError, InvalidFrameError

PROTOCOL_VERSION = 0x01
VERSION_SIZE = 1
NONCE_SIZE = 12
TAG_SIZE = 16
KEY_SIZE = 32
MIN_FRAME_SIZE = VERSION_SIZE + NONCE_SIZE + TAG_SIZE # 29 byts

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    """
    Encrypt plaintext with AES-256-GCM.

    Args:
        key: 32-byte symmetric key.
        plaintext: arbitrary-length plaintext.

    Returns:
        Complete wire frame: version || nonce || ciphertext || tag.
    """
    _validate_key(key)

    nonce = os.urandom(NONCE_SIZE)
    aad = struct.pack("B", PROTOCOL_VERSION) # version as 1 byte
    ct_and_tag = AESGCM(key).encrypt(nonce, plaintext, aad)

    return struct.pack("B", PROTOCOL_VERSION) + nonce + ct_and_tag


def decrypt(key: bytes, frame: bytes) -> bytes:
    """
    Decrypt and authenticate a wire frame.

    Args:
        key: 32-byte symmetric key.
        frame: complete wire frame.

    Returns:
        Decrypted plaintext.

    Raises:
        InvalidFrameError: frame too short or unknown version.
        DecryptionError: authentication failed (tampered/corrupt/wrong key).
    """
    _validate_key(key)

    if len(frame) < MIN_FRAME_SIZE:
        raise InvalidFrameError(f"Frame too short: {len(frame)} < {MIN_FRAME_SIZE}")
    
    version = frame[0]
    if version != PROTOCOL_VERSION:
        raise InvalidFrameError(f"Unknown protocol version: {version}")
    
    nonce = frame[VERSION_SIZE : VERSION_SIZE + NONCE_SIZE]
    ct_and_tag = frame[VERSION_SIZE + NONCE_SIZE :]
    aad = struct.pack("B", version)

    try:
        return AESGCM(key).decrypt(nonce, ct_and_tag, aad)
    except InvalidTag:
        raise DecryptionError("Authentication failed")


def _validate_key(key: bytes):
    if not isinstance(key, bytes):
        raise ValueError("Key must be bytes.")
    if len(key) != KEY_SIZE:
        raise ValueError(f"Key must be {KEY_SIZE} bytes long.")