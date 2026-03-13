"""Tests for AES-256-GCM symmetric encryption."""

import os
import pytest
from crypto.symmetric import encrypt, decrypt, PROTOCOL_VERSION, KEY_SIZE
from crypto.errors import DecryptionError, InvalidFrameError


@pytest.fixture
def key():
    return os.urandom(KEY_SIZE)


class TestRoundTrip:
    """Encrypt then decrypt should return original plaintext."""

    def test_basic_roundtrip(self, key):
        pt = b"hello over acoustic channel"
        assert decrypt(key, encrypt(key, pt)) == pt

    def test_empty_plaintext(self, key):
        assert decrypt(key, encrypt(key, b"")) == b""

    def test_max_payload(self, key):
        pt = os.urandom(256)  # max realistic ggwave payload
        assert decrypt(key, encrypt(key, pt)) == pt

    def test_unicode_roundtrip(self, key):
        pt = "meet at café ☕".encode("utf-8")
        assert decrypt(key, encrypt(key, pt)) == pt


class TestNonceUniqueness:
    """Every encryption must produce a different nonce."""

    def test_different_nonces(self, key):
        pt = b"same plaintext"
        frame1 = encrypt(key, pt)
        frame2 = encrypt(key, pt)
        nonce1 = frame1[1:13]
        nonce2 = frame2[1:13]
        assert nonce1 != nonce2, "Nonce reuse detected!"

    def test_different_ciphertexts(self, key):
        pt = b"same plaintext"
        assert encrypt(key, pt) != encrypt(key, pt)


class TestTamperDetection:
    """Any modification to the frame must cause decryption to fail."""

    def test_bitflip_ciphertext(self, key):
        frame = bytearray(encrypt(key, b"secret"))
        frame[15] ^= 0x01  # flip one bit in ciphertext
        with pytest.raises(DecryptionError):
            decrypt(key, bytes(frame))

    def test_bitflip_nonce(self, key):
        frame = bytearray(encrypt(key, b"secret"))
        frame[1] ^= 0x01  # flip one bit in nonce
        with pytest.raises(DecryptionError):
            decrypt(key, bytes(frame))

    def test_bitflip_version(self, key):
        frame = bytearray(encrypt(key, b"secret"))
        frame[0] ^= 0x01  # flip version (AAD)
        with pytest.raises(InvalidFrameError):
            decrypt(key, bytes(frame))

    def test_truncated_frame(self, key):
        frame = encrypt(key, b"secret")
        with pytest.raises((InvalidFrameError, DecryptionError)):
            decrypt(key, frame[:20])

    def test_wrong_key(self, key):
        frame = encrypt(key, b"secret")
        wrong_key = os.urandom(KEY_SIZE)
        with pytest.raises(DecryptionError):
            decrypt(wrong_key, frame)


class TestEdgeCases:
    def test_invalid_key_length(self):
        with pytest.raises(ValueError):
            encrypt(b"short", b"data")

    def test_empty_frame(self, key):
        with pytest.raises(InvalidFrameError):
            decrypt(key, b"")