"""Custom exceptions for the crypto module."""


class CryptoError(Exception):
    """Base class for all crypto errors."""


class DecryptionError(CryptoError):
    """Raised when decryption or authentication fails."""


class InvalidFrameError(CryptoError):
    """Raised when a wire frame is malformed."""


class HandshakeError(CryptoError):
    """Raised when the key exchange handshake fails."""


class CommitmentMismatchError(HandshakeError):
    """Raised when the commitment doesn't match the reveal."""