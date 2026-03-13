"""
Handshake coordinator — orchestrates X25519 key exchange over acoustic channel.

This module bridges the crypto layer (keyexchange.py) with the transport layer
(Sender/Receiver). It manages the multi-step handshake state machine and
invokes callbacks when the handshake completes or fails.

Usage:
    coordinator = HandshakeCoordinator(sender, on_complete, on_fail)
    coordinator.start_as_initiator() # or wait for incoming commitment
    # ... Receiver routes handshake frames to coordinator.handle_frame() ...
    # on_complete(session_key, sas) fires when the exchange finishes
"""

from crypto.keyexchange import Initiator, Responder
from crypto.framing import FrameType
from crypto.errors import CommitmentMismatchError, HandshakeError

from typing import Callable


class HandshakeCoordinator:
    """
    Orchestrates the X25519 + commit-reveal key exchange over acoustic frames.

    Delegates actual cryptography to crypto.keyexchange.Initiator/Responder.
    Delegates frame transmission to Sender.send_handshake_frame().
    """

    def __init__(
        self,
        sender,  # Sender instance — used to transmit handshake frames
        on_complete: Callable[[bytes, str], None] | None = None,
        on_fail: Callable[[str], None] | None = None,
    ):
        """
        Args:
            sender: Sender instance with send_handshake_frame() method.
            on_complete: Called with (session_key, sas) on success.
            on_fail: Called with (reason) on failure.
        """
        self.sender = sender
        self.on_complete = on_complete
        self.on_fail = on_fail

        self._initiator: Initiator | None = None
        self._responder: Responder | None = None
        self._role: str | None = None
        self._session_key: bytes | None = None
        self._sas: str | None = None

    @property
    def role(self) -> str | None:
        """Current role: 'initiator', 'responder', or None if undecided."""
        return self._role

    @property
    def session_key(self) -> bytes | None:
        return self._session_key

    @property
    def sas(self) -> str | None:
        return self._sas

    def start_as_initiator(self) -> None:
        """
        Begin the handshake as the initiator (Device A).

        Sends the commitment frame and transitions to waiting for pk_b.
        """
        self._role = "initiator"
        self._initiator = Initiator()
        commitment = self._initiator.get_commitment()
        self.sender.send_handshake_frame(
            FrameType.HANDSHAKE_COMMITMENT, commitment
        )

    def handle_frame(self, frame_type: FrameType, payload: bytes) -> None:
        """
        Route an incoming handshake frame to the correct handler.

        Called by the Receiver's on_handshake_frame callback.
        """
        handlers = {
            FrameType.HANDSHAKE_COMMITMENT: self._handle_commitment,
            FrameType.HANDSHAKE_PK: self._handle_pk,
            FrameType.HANDSHAKE_REVEAL: self._handle_reveal,
        }

        handler = handlers.get(frame_type)
        if handler:
            handler(payload)

    def _handle_commitment(self, payload: bytes) -> None:
        """
        Received a commitment - we're the responder.
        Generate our keypair and send pk_b back.
        """
        if self._role is not None:
            # Already in a handshake — ignore duplicate commitments
            return

        self._role = "responder"
        self._responder = Responder()
        pk_b = self._responder.receive_commitment(payload)
        self.sender.send_handshake_frame(FrameType.HANDSHAKE_PK, pk_b)

    def _handle_pk(self, payload: bytes) -> None:
        """
        Received responder's public key - we're the initiator.
        Compute shared secret and send the reveal.
        """
        if self._role != "initiator" or self._initiator is None:
            return

        reveal = self._initiator.receive_public_key_and_reveal(payload)
        self.sender.send_handshake_frame(FrameType.HANDSHAKE_REVEAL, reveal)

        self._session_key = self._initiator.session_key
        self._sas = self._initiator.sas
        self._finish()

    def _handle_reveal(self, payload: bytes) -> None:
        """
        Received the initiator's reveal - we're the responder.
        Verify commitment and compute shared secret.
        """
        if self._role != "responder" or self._responder is None:
            return

        try:
            self._responder.receive_reveal(payload)
        except (CommitmentMismatchError, HandshakeError) as e:
            self._fail(f"Handshake failed: {e}")
            return

        self._session_key = self._responder.session_key
        self._sas = self._responder.sas
        self._finish()

    def _finish(self) -> None:
        """Handshake complete - invoke success callback."""
        if self.on_complete and self._session_key and self._sas:
            self.on_complete(self._session_key, self._sas)

    def _fail(self, reason: str) -> None:
        """Handshake failed - invoke failure callback and reset."""
        self._role = None
        self._initiator = None
        self._responder = None
        self._session_key = None
        self._sas = None
        if self.on_fail:
            self.on_fail(reason)