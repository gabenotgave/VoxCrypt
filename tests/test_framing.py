"""Tests for wire frame encoding/decoding."""

import os
import pytest
from crypto.framing import (
    FrameType,
    encode_frame,
    decode_frame,
    EXPECTED_SIZES,
    FRAME_TYPE_SIZE,
)


class TestRoundTrip:
    """encode_frame → decode_frame should return the original type + payload."""

    def test_handshake_commitment(self):
        payload = os.urandom(32)
        frame = encode_frame(FrameType.HANDSHAKE_COMMITMENT, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.HANDSHAKE_COMMITMENT
        assert decoded_payload == payload

    def test_handshake_pk(self):
        payload = os.urandom(32)
        frame = encode_frame(FrameType.HANDSHAKE_PK, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.HANDSHAKE_PK
        assert decoded_payload == payload

    def test_handshake_reveal(self):
        payload = os.urandom(48)
        frame = encode_frame(FrameType.HANDSHAKE_REVEAL, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.HANDSHAKE_REVEAL
        assert decoded_payload == payload

    def test_encrypted_data(self):
        # version(1) + nonce(12) + ciphertext(N) + tag(16)
        payload = os.urandom(1 + 12 + 20 + 16)
        frame = encode_frame(FrameType.ENCRYPTED_DATA, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.ENCRYPTED_DATA
        assert decoded_payload == payload

    def test_ack(self):
        payload = b"\x01"
        frame = encode_frame(FrameType.ACK, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.ACK
        assert decoded_payload == payload

    def test_empty_encrypted_payload(self):
        """Encrypted data with zero-length plaintext still has ver+nonce+tag."""
        payload = os.urandom(1 + 12 + 16)  # no ciphertext body
        frame = encode_frame(FrameType.ENCRYPTED_DATA, payload)
        frame_type, decoded_payload = decode_frame(frame)
        assert frame_type == FrameType.ENCRYPTED_DATA
        assert decoded_payload == payload


class TestFrameStructure:
    """Verify the raw byte layout of encoded frames."""

    def test_first_byte_is_frame_type(self):
        payload = os.urandom(32)
        frame = encode_frame(FrameType.HANDSHAKE_COMMITMENT, payload)
        assert frame[0] == FrameType.HANDSHAKE_COMMITMENT

    def test_payload_follows_type_byte(self):
        payload = os.urandom(32)
        frame = encode_frame(FrameType.HANDSHAKE_PK, payload)
        assert frame[FRAME_TYPE_SIZE:] == payload

    def test_total_length(self):
        payload = os.urandom(48)
        frame = encode_frame(FrameType.HANDSHAKE_REVEAL, payload)
        assert len(frame) == FRAME_TYPE_SIZE + len(payload)


class TestHandshakePayloadValidation:
    """Fixed-size handshake frames must reject wrong-sized payloads."""

    @pytest.mark.parametrize("frame_type, expected_size", [
        (FrameType.HANDSHAKE_COMMITMENT, 32),
        (FrameType.HANDSHAKE_PK, 32),
        (FrameType.HANDSHAKE_REVEAL, 48),
    ])
    def test_correct_size_accepted(self, frame_type, expected_size):
        payload = os.urandom(expected_size)
        frame = encode_frame(frame_type, payload)
        decoded_type, decoded_payload = decode_frame(frame)
        assert decoded_type == frame_type
        assert decoded_payload == payload

    @pytest.mark.parametrize("frame_type, expected_size", [
        (FrameType.HANDSHAKE_COMMITMENT, 32),
        (FrameType.HANDSHAKE_PK, 32),
        (FrameType.HANDSHAKE_REVEAL, 48),
    ])
    def test_too_short_rejected(self, frame_type, expected_size):
        payload = os.urandom(expected_size - 1)
        frame = encode_frame(frame_type, payload)
        with pytest.raises(ValueError, match="expected"):
            decode_frame(frame)

    @pytest.mark.parametrize("frame_type, expected_size", [
        (FrameType.HANDSHAKE_COMMITMENT, 32),
        (FrameType.HANDSHAKE_PK, 32),
        (FrameType.HANDSHAKE_REVEAL, 48),
    ])
    def test_too_long_rejected(self, frame_type, expected_size):
        payload = os.urandom(expected_size + 1)
        frame = encode_frame(frame_type, payload)
        with pytest.raises(ValueError, match="expected"):
            decode_frame(frame)


class TestVariableLengthFrames:
    """ENCRYPTED_DATA and ACK have no fixed payload size constraint."""

    def test_encrypted_data_various_sizes(self):
        for size in [29, 50, 100, 256]:
            payload = os.urandom(size)
            frame = encode_frame(FrameType.ENCRYPTED_DATA, payload)
            frame_type, decoded = decode_frame(frame)
            assert frame_type == FrameType.ENCRYPTED_DATA
            assert decoded == payload

    def test_ack_various_sizes(self):
        for size in [1, 12, 16]:
            payload = os.urandom(size)
            frame = encode_frame(FrameType.ACK, payload)
            frame_type, decoded = decode_frame(frame)
            assert frame_type == FrameType.ACK
            assert decoded == payload


class TestMalformedInput:
    """decode_frame must reject garbage gracefully."""

    def test_empty_bytes(self):
        with pytest.raises(ValueError, match="too short"):
            decode_frame(b"")

    def test_unknown_frame_type(self):
        # 0xFF is not a valid FrameType
        bad_frame = b"\xff" + os.urandom(32)
        with pytest.raises(ValueError, match="Unknown frame type"):
            decode_frame(bad_frame)

    def test_type_byte_only_no_payload(self):
        """A commitment frame with zero payload bytes should fail validation."""
        frame = bytes([FrameType.HANDSHAKE_COMMITMENT])
        with pytest.raises(ValueError, match="expected"):
            decode_frame(frame)

    def test_another_unknown_type(self):
        bad_frame = b"\xaa" + os.urandom(10)
        with pytest.raises(ValueError, match="Unknown frame type"):
            decode_frame(bad_frame)


class TestFrameTypeValues:
    """Ensure frame type constants haven't drifted — protocol compatibility."""

    def test_handshake_commitment_value(self):
        assert FrameType.HANDSHAKE_COMMITMENT == 0x01

    def test_handshake_pk_value(self):
        assert FrameType.HANDSHAKE_PK == 0x02

    def test_handshake_reveal_value(self):
        assert FrameType.HANDSHAKE_REVEAL == 0x03

    def test_encrypted_data_value(self):
        assert FrameType.ENCRYPTED_DATA == 0x10

    def test_ack_value(self):
        assert FrameType.ACK == 0x11


class TestCrossLayerIntegration:
    """Verify framing works correctly with real crypto output."""

    def test_framing_with_real_encrypted_payload(self):
        """Encrypt a message, frame it, decode the frame, decrypt."""
        from crypto.symmetric import encrypt as aes_encrypt, decrypt as aes_decrypt

        key = os.urandom(32)
        plaintext = b"hello over acoustic channel"

        # Encrypt → frame → decode → decrypt
        encrypted = aes_encrypt(key, plaintext)
        frame = encode_frame(FrameType.ENCRYPTED_DATA, encrypted)
        frame_type, payload = decode_frame(frame)
        decrypted = aes_decrypt(key, payload)

        assert frame_type == FrameType.ENCRYPTED_DATA
        assert decrypted == plaintext

    def test_tampered_framed_payload_fails_decrypt(self):
        """Flip a bit in the framed ciphertext — decryption must fail."""
        from crypto.symmetric import encrypt as aes_encrypt, decrypt as aes_decrypt
        from crypto.errors import DecryptionError

        key = os.urandom(32)
        encrypted = aes_encrypt(key, b"secret message")
        frame = bytearray(encode_frame(FrameType.ENCRYPTED_DATA, encrypted))

        # Flip a bit somewhere in the ciphertext region
        # Frame: [type:1] [version:1] [nonce:12] [ct...] [tag:16]
        tamper_index = FRAME_TYPE_SIZE + 1 + 12 + 2  # inside ciphertext
        if tamper_index < len(frame) - 16:
            frame[tamper_index] ^= 0x01

        frame_type, payload = decode_frame(bytes(frame))
        with pytest.raises(DecryptionError):
            aes_decrypt(key, payload)