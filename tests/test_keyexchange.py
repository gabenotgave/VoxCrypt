"""Tests for X25519 key exchange with commitment and SAS."""

import pytest
from crypto.keyexchange import Initiator, Responder
from crypto.errors import CommitmentMismatchError, HandshakeError


class TestHappyPath:
    """Normal handshake between honest parties."""

    def test_both_derive_same_key(self):
        init = Initiator()
        resp = Responder()

        commitment = init.get_commitment()
        pk_b = resp.receive_commitment(commitment)
        reveal = init.receive_public_key_and_reveal(pk_b)
        resp.receive_reveal(reveal)

        assert init.session_key == resp.session_key
        assert len(init.session_key) == 32

    def test_both_derive_same_sas(self):
        init = Initiator()
        resp = Responder()

        commitment = init.get_commitment()
        pk_b = resp.receive_commitment(commitment)
        reveal = init.receive_public_key_and_reveal(pk_b)
        resp.receive_reveal(reveal)

        assert init.sas == resp.sas
        assert len(init.sas) == 6
        assert init.sas.isdigit()

    def test_different_sessions_different_keys(self):
        """Each handshake must produce unique keys (ephemeral keypairs)."""
        keys = set()
        for _ in range(10):
            init = Initiator()
            resp = Responder()
            commitment = init.get_commitment()
            pk_b = resp.receive_commitment(commitment)
            reveal = init.receive_public_key_and_reveal(pk_b)
            resp.receive_reveal(reveal)
            keys.add(init.session_key)
        assert len(keys) == 10


class TestMITMDetection:
    """Commitment mismatch must abort the handshake."""

    def test_tampered_commitment(self):
        init = Initiator()
        resp = Responder()

        commitment = bytearray(init.get_commitment())
        commitment[0] ^= 0xFF  # tamper
        pk_b = resp.receive_commitment(bytes(commitment))
        reveal = init.receive_public_key_and_reveal(pk_b)

        with pytest.raises(CommitmentMismatchError):
            resp.receive_reveal(reveal)

    def test_tampered_reveal(self):
        init = Initiator()
        resp = Responder()

        commitment = init.get_commitment()
        pk_b = resp.receive_commitment(commitment)
        reveal = bytearray(init.receive_public_key_and_reveal(pk_b))
        reveal[0] ^= 0xFF  # tamper with pk_a

        with pytest.raises(CommitmentMismatchError):
            resp.receive_reveal(bytes(reveal))

    def test_substituted_public_key(self):
        """Attacker substitutes their own pk_b — SAS will differ."""
        init = Initiator()
        resp = Responder()
        attacker = Responder()  # attacker generates their own keypair

        commitment = init.get_commitment()
        _pk_b_real = resp.receive_commitment(commitment)
        pk_b_fake = attacker.receive_commitment(commitment)

        reveal = init.receive_public_key_and_reveal(pk_b_fake)
        resp.receive_reveal(reveal)  # commitment still valid (it's about pk_a)

        # But the SAS codes will NOT match — human catches this
        assert init.sas != resp.sas