import threading
import pyaudio
import ggwave
from utils import suppress_stdout_stderr
from crypto.symmetric import decrypt as aes_decrypt
from crypto.framing import FrameType, decode_frame
from crypto.errors import CryptoError
import time
import base64

class Receiver:
    def __init__(
        self,
        input_device_index=None,
        on_message_received=None,
        on_handshake_frame=None,
        session_key=None,
    ):

        self.input_device_index = input_device_index
        self.on_message_received = on_message_received  # <-- no comma
        self.on_handshake_frame = on_handshake_frame
        self.session_key = session_key
        self.running = True

        # Start the listening thread
        self.thread = threading.Thread(target=self._listen, daemon=True)
        self.thread.start()
    
    def _listen(self):
        # Brief delay to let app finish mounting
        time.sleep(0.01)
        self.ggwave_instance = ggwave.init()

        with suppress_stdout_stderr():
            p = pyaudio.PyAudio()

            # Open the microphone stream
            stream = p.open(
                format=pyaudio.paFloat32,
                channels=1,
                rate=48000,
                input=True,
                frames_per_buffer=1024,
                input_device_index=self.input_device_index
            )

        while self.running:
            try:
                # Read a chunk of audio
                # exception_on_overflow=False prevents errors if the CPU gets busy
                data = stream.read(1024, exception_on_overflow=False)

                # Feed the chunk to ggwave
                # Returns a result only when a full message has been found in this chunk
                with suppress_stdout_stderr():
                    result = ggwave.decode(self.ggwave_instance, data)

                if result:
                    self._route_frame(result)

            except Exception as e:
                if self.on_message_received:
                    self.on_message_received(f"[Receiver Error]: {str(e)}")

        # Clean up audio resources
        with suppress_stdout_stderr():
            stream.stop_stream()
            stream.close()
            p.terminate()
            ggwave.free(self.ggwave_instance)
    
    def _route_frame(self, raw_bytes: bytes):
        """
        Determine if the frame is a handshake, encrypted data, or legacy
        plaintext, and route to the correct handler.
        """
        # ggwave gives us bytes — first decode to string
        try:
            raw_str = raw_bytes.decode("utf-8") if isinstance(raw_bytes, bytes) else raw_bytes
        except UnicodeDecodeError:
            return  # garbage — drop

        # Try to base64-decode (framed binary messages are base64-encoded)
        frame_bytes = None
        try:
            frame_bytes = base64.b64decode(raw_str, validate=True)
        except Exception:
            pass  # not base64 — might be legacy plaintext

        # If we got binary data, try to parse as a typed frame
        if frame_bytes is not None:
            try:
                frame_type, payload = decode_frame(frame_bytes)

                # Handshake frames → route to handshake handler
                if frame_type in (
                    FrameType.HANDSHAKE_COMMITMENT,
                    FrameType.HANDSHAKE_PK,
                    FrameType.HANDSHAKE_REVEAL,
                ):
                    if self.on_handshake_frame:
                        self.on_handshake_frame(frame_type, payload)
                    return

                # Encrypted data or ACK → decrypt
                if frame_type in (FrameType.ENCRYPTED_DATA, FrameType.ACK):
                    if not self.session_key:
                        return  # no session yet — drop silently

                    try:
                        plaintext = aes_decrypt(self.session_key, payload)
                        text = plaintext.decode("utf-8")
                        if self.on_message_received:
                            self.on_message_received(text)
                        return
                    except CryptoError:
                        return  # tampered or wrong key — drop silently

            except ValueError:
                pass  # valid base64 but not a valid frame — fall through

        # Legacy plaintext fallback (only if no active session key).
        # Once a secure session is established, ignore unauthenticated plaintext
        # so an attacker cannot inject spoofed messages.
        if not self.session_key and self.on_message_received:
            self.on_message_received(raw_str)

    def stop(self):
        """Stop the receiver and wait for the thread to exit."""
        self.running = False
        self.thread.join(timeout=3.0)  # block until the listen thread dies