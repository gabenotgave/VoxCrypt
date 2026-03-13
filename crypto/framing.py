"""
Wire format for all acoustic frame types.

Frame layout:
  [type: 1B] [payload: variable]

Types:
  0x01  HANDSHAKE_COMMITMENT   payload = commitment (32B)
  0x02  HANDSHAKE_PK           payload = public_key (32B)
  0x03  HANDSHAKE_REVEAL       payload = pk_a || random_a (48B)
  0x10  ENCRYPTED_DATA         payload = version(1B) || nonce(12B) || ct || tag(16B)
  0x11  ACK                    payload = nonce_echo(12B)  [encrypted]
"""

from enum import IntEnum
import struct

class FrameType(IntEnum):
    HANDSHAKE_COMMITMENT = 0x01
    HANDSHAKE_PK = 0x02
    HANDSHAKE_REVEAL = 0x03
    ENCRYPTED_DATA = 0x10
    ACK = 0x11

FRAME_TYPE_SIZE = 1

# Expected payload sizes for handshake frames
EXPECTED_SIZES = {
    FrameType.HANDSHAKE_COMMITMENT: 32,
    FrameType.HANDSHAKE_PK: 32,
    FrameType.HANDSHAKE_REVEAL: 48,
}

def encode_frame(frame_type: FrameType, payload: bytes) -> bytes:
    """Wrap a payload with its frame type header."""
    return struct.pack("B", frame_type) + payload

def decode_frame(data: bytes) -> tuple[FrameType, bytes]:
    """
    Parse a raw acoustic frame into (type, payload).

    Raises:
        ValueError: if frame is empty or type is unknown.
    """
    if len(data) < FRAME_TYPE_SIZE:
        raise ValueError("Frame too short")
    
    try:
        frame_type = FrameType(data[0])
    except ValueError:
        raise ValueError(f"Unknown frame type: 0x{data[0]:02x}")
    
    payload = data[FRAME_TYPE_SIZE:]

    # Validate fixed-size handshake frames
    if frame_type in EXPECTED_SIZES:
        expected = EXPECTED_SIZES[frame_type]
        if len(payload) != expected:
            raise ValueError(
                f"{frame_type.name}: expected {expected}B payload, "
                f"got {len(payload)}B"
            )
    
    return frame_type, payload