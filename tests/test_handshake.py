"""Tests for the HandshakeCoordinator over simulated acoustic transport."""

import pytest
from unittest.mock import MagicMock, call
from transport.handshake import HandshakeCoordinator
from crypto.framing import FrameType


class FakeSender:
    """Captures handshake frames instead of playing audio."""

    def __init__(self):
        self.sent_frames: list[tuple[FrameType, bytes]] = []

    def send_handshake_frame(self, frame_type: FrameType, payload: bytes):
        self.sent_frames.append((frame_type, payload))


def run_full_handshake():
    """
    Simulate a complete handshake between two coordinators
    by manually passing frames between them.

    Returns (coordinator_a, coordinator_b, result_a, result_b)
    """
    sender_a = FakeSender()
    sender_b = FakeSender()

    result_a = {"key": None, "sas": None}
    result_b = {"key": None, "sas": None}

    def on_complete_a(key, sas):
        result_a["key"] = key
        result_a["sas"] = sas

    def on_complete_b(key, sas):
        result_b["key"] = key
        result_b["sas"] = sas

    coord_a = HandshakeCoordinator(sender_a, on_complete=on_complete_a)
    coord_b = HandshakeCoordinator(sender_b, on_complete=on_complete_b)

    # Step 1: A initiates → sends COMMITMENT
    coord_a.start_as_initiator()
    assert len(sender_a.sent_frames) == 1
    commit_type, commit_payload = sender_a.sent_frames[0]
    assert commit_type == FrameType.HANDSHAKE_COMMITMENT

    # Step 2: B receives COMMITMENT → sends PK
    coord_b.handle_frame(commit_type, commit_payload)
    assert len(sender_b.sent_frames) == 1
    pk_type, pk_payload = sender_b.sent_frames[0]
    assert pk_type == FrameType.HANDSHAKE_PK

    # Step 3: A receives PK → sends REVEAL
    coord_a.handle_frame(pk_type, pk_payload)
    assert len(sender_a.sent_frames) == 2
    reveal_type, reveal_payload = sender_a.sent_frames[1]
    assert reveal_type == FrameType.HANDSHAKE_REVEAL

    # Step 4: B receives REVEAL → handshake complete
    coord_b.handle_frame(reveal_type, reveal_payload)

    return coord_a, coord_b, result_a, result_b


class TestHappyPath:
    def test_both_sides_complete(self):
        _, _, result_a, result_b = run_full_handshake()
        assert result_a["key"] is not None
        assert result_b["key"] is not None

    def test_session_keys_match(self):
        _, _, result_a, result_b = run_full_handshake()
        assert result_a["key"] == result_b["key"]
        assert len(result_a["key"]) == 32

    def test_sas_codes_match(self):
        _, _, result_a, result_b = run_full_handshake()
        assert result_a["sas"] == result_b["sas"]
        assert len(result_a["sas"]) == 6
        assert result_a["sas"].isdigit()

    def test_roles_assigned_correctly(self):
        coord_a, coord_b, _, _ = run_full_handshake()
        assert coord_a.role == "initiator"
        assert coord_b.role == "responder"

    def test_unique_keys_per_handshake(self):
        keys = set()
        for _ in range(5):
            _, _, result_a, _ = run_full_handshake()
            keys.add(result_a["key"])
        assert len(keys) == 5


class TestFrameSequence:
    """Verify the exact sequence of frames transmitted."""

    def test_initiator_sends_commitment_then_reveal(self):
        sender_a = FakeSender()
        sender_b = FakeSender()
        coord_a = HandshakeCoordinator(sender_a)
        coord_b = HandshakeCoordinator(sender_b)

        coord_a.start_as_initiator()
        coord_b.handle_frame(*sender_a.sent_frames[0])
        coord_a.handle_frame(*sender_b.sent_frames[0])

        types_sent_by_a = [f[0] for f in sender_a.sent_frames]
        assert types_sent_by_a == [
            FrameType.HANDSHAKE_COMMITMENT,
            FrameType.HANDSHAKE_REVEAL,
        ]

    def test_responder_sends_only_pk(self):
        sender_a = FakeSender()
        sender_b = FakeSender()
        coord_a = HandshakeCoordinator(sender_a)
        coord_b = HandshakeCoordinator(sender_b)

        coord_a.start_as_initiator()
        coord_b.handle_frame(*sender_a.sent_frames[0])

        types_sent_by_b = [f[0] for f in sender_b.sent_frames]
        assert types_sent_by_b == [FrameType.HANDSHAKE_PK]

    def test_payload_sizes(self):
        sender_a = FakeSender()
        sender_b = FakeSender()
        coord_a = HandshakeCoordinator(sender_a)
        coord_b = HandshakeCoordinator(sender_b)

        coord_a.start_as_initiator()
        coord_b.handle_frame(*sender_a.sent_frames[0])
        coord_a.handle_frame(*sender_b.sent_frames[0])
        coord_b.handle_frame(*sender_a.sent_frames[1])

        # Commitment: 32 bytes (SHA-256 hash)
        assert len(sender_a.sent_frames[0][1]) == 32
        # PK: 32 bytes (X25519 public key)
        assert len(sender_b.sent_frames[0][1]) == 32
        # Reveal: 48 bytes (32 pk + 16 random)
        assert len(sender_a.sent_frames[1][1]) == 48


class TestMITMDetection:
    """Simulated man-in-the-middle attack."""

    def test_mitm_causes_sas_mismatch(self):
        """
        Attacker intercepts and runs separate handshakes with A and B.
        The SAS codes will not match.
        """
        sender_a = FakeSender()
        sender_b = FakeSender()
        sender_m_to_a = FakeSender()  # Mallory pretending to be B
        sender_m_to_b = FakeSender()  # Mallory pretending to be A

        result_a = {"sas": None}
        result_b = {"sas": None}

        coord_a = HandshakeCoordinator(
            sender_a, on_complete=lambda k, s: result_a.update({"sas": s})
        )
        coord_b = HandshakeCoordinator(
            sender_b, on_complete=lambda k, s: result_b.update({"sas": s})
        )
        mallory_to_a = HandshakeCoordinator(sender_m_to_a)
        mallory_to_b = HandshakeCoordinator(sender_m_to_b)

        # A → Mallory (Mallory intercepts commitment)
        coord_a.start_as_initiator()
        commit = sender_a.sent_frames[0]
        mallory_to_a.handle_frame(*commit)  # Mallory acts as responder to A

        # Mallory → B (Mallory starts a fresh handshake with B as initiator)
        mallory_to_b.start_as_initiator()
        coord_b.handle_frame(*sender_m_to_b.sent_frames[0])

        # B → Mallory (B sends pk_b)
        mallory_to_b.handle_frame(*sender_b.sent_frames[0])

        # Mallory → A (Mallory sends her own pk to A)
        coord_a.handle_frame(*sender_m_to_a.sent_frames[0])

        # A → Mallory (A sends reveal)
        mallory_to_a.handle_frame(*sender_a.sent_frames[1])

        # Mallory → B (Mallory sends her reveal to B)
        coord_b.handle_frame(*sender_m_to_b.sent_frames[1])

        # Both sides completed — but SAS codes MUST differ
        assert result_a["sas"] is not None
        assert result_b["sas"] is not None
        assert result_a["sas"] != result_b["sas"]  # MITM detected!


class TestEdgeCases:
    def test_duplicate_commitment_ignored(self):
        """Receiving a second commitment after already being a responder."""
        sender_a = FakeSender()
        sender_b = FakeSender()
        coord_b = HandshakeCoordinator(sender_b)

        # First commitment — B becomes responder
        commitment = b"\x00" * 32
        coord_b.handle_frame(FrameType.HANDSHAKE_COMMITMENT, commitment)
        assert coord_b.role == "responder"
        assert len(sender_b.sent_frames) == 1

        # Second commitment — should be ignored
        coord_b.handle_frame(FrameType.HANDSHAKE_COMMITMENT, b"\xff" * 32)
        assert len(sender_b.sent_frames) == 1  # no new frame sent

    def test_pk_ignored_if_not_initiator(self):
        """Receiving a PK frame when we haven't initiated."""
        sender = FakeSender()
        coord = HandshakeCoordinator(sender)

        # We never called start_as_initiator()
        coord.handle_frame(FrameType.HANDSHAKE_PK, b"\x00" * 32)
        assert len(sender.sent_frames) == 0  # nothing sent
        assert coord.role is None

    def test_reveal_ignored_if_not_responder(self):
        """Receiving a reveal frame when we haven't responded to a commitment."""
        sender = FakeSender()
        coord = HandshakeCoordinator(sender)

        coord.handle_frame(FrameType.HANDSHAKE_REVEAL, b"\x00" * 48)
        assert len(sender.sent_frames) == 0
        assert coord.role is None

    def test_tampered_reveal_triggers_on_fail(self):
        """If the reveal doesn't match the commitment, on_fail is called."""
        sender_a = FakeSender()
        sender_b = FakeSender()
        fail_reason = {"msg": None}

        coord_a = HandshakeCoordinator(sender_a)
        coord_b = HandshakeCoordinator(
            sender_b, on_fail=lambda r: fail_reason.update({"msg": r})
        )

        coord_a.start_as_initiator()
        coord_b.handle_frame(*sender_a.sent_frames[0])
        coord_a.handle_frame(*sender_b.sent_frames[0])

        # Tamper with the reveal
        reveal_type, reveal_payload = sender_a.sent_frames[1]
        tampered = bytearray(reveal_payload)
        tampered[0] ^= 0xFF
        coord_b.handle_frame(reveal_type, bytes(tampered))

        assert fail_reason["msg"] is not None
        assert "failed" in fail_reason["msg"].lower()
        assert coord_b.role is None  # reset after failure
        assert coord_b.session_key is None

    def test_on_complete_not_called_on_failure(self):
        """on_complete must NOT fire if the handshake fails."""
        sender_a = FakeSender()
        sender_b = FakeSender()
        complete_called = {"called": False}

        coord_b = HandshakeCoordinator(
            sender_b,
            on_complete=lambda k, s: complete_called.update({"called": True}),
            on_fail=lambda r: None,
        )

        coord_a = HandshakeCoordinator(sender_a)
        coord_a.start_as_initiator()
        coord_b.handle_frame(*sender_a.sent_frames[0])
        coord_a.handle_frame(*sender_b.sent_frames[0])

        # Send garbage reveal
        coord_b.handle_frame(FrameType.HANDSHAKE_REVEAL, b"\x00" * 48)

        assert not complete_called["called"]