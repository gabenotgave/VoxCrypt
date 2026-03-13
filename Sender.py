import ggwave
import pyaudio
import queue
import threading
import time
import random
import string
from utils import suppress_stdout_stderr
from crypto.symmetric import encrypt as aes_encrypt
from crypto.framing import FrameType, encode_frame
import base64

class Sender():

    MAX_RETRIES = 3 # Max number of times to resend a message if no ACK is received

    def __init__(self, name, protocol_id=1, on_status_update=None, output_device_index=None, session_key=None):
        self.name = name # Stores username to attach to messages
        self.on_status_update = on_status_update # Store callback function for status updates (optional)
        self._PROTOCOL_ID = protocol_id
        self._output_device_index = output_device_index

        self.session_key = session_key

        self.msg_queue = queue.Queue()

        # A "Thread Event" is like a flag
        # Set() raises the flag (True), Clear() lowers it (False)
        # Threads can wait() for the flag to be raised
        self.ack_received_event = threading.Event()

        self.current_expected_ack_id = None

        self.running = True

        # Creates a background thread that runs the '_process_queue' method
        # deamon=True means this thread will automatically die when the main app closes
        self.worker_thread = threading.Thread(target=self._process_queue, daemon=True)
        self.worker_thread.start() # Actually starts that background thread running

    def send_message(self, message):
        # Puts a message into the waiting line
        self.msg_queue.put(message)
    
    def send_ack(self, packet_id):
        # Starts a new temporary thread just to play the "ACK" sound
        # This is done so that the ACK doesn't get stuck waiting in the queue behind other messages
        threading.Thread(target=self._transmit, args=(f"ACK:{packet_id}",), daemon=True).start()
    
    def send_handshake_frame(self, frame_type: FrameType, payload: bytes):
        """Send a handshake frame directly — bypasses encryption and queue."""
        raw_frame = encode_frame(frame_type, payload)
        threading.Thread(
            target=self._play_audio_bytes,
            args=(raw_frame,),
            daemon=True,
        ).start()
    
    def notify_ack(self):
        # Called by the App when it hears an ACK from the other person
        # Raises the flag (sets it to True), telling the waiting threat it can stop retrying
        self.ack_received_event.set()
    
    def _transmit(self, message: str):
        """Encrypt (if session active) and play audio."""
        if self.session_key:
            # Encrypt the full text payload, then wrap as ENCRYPTED_DATA frame
            plaintext = message.encode("utf-8")
            encrypted = aes_encrypt(self.session_key, plaintext)
            frame = encode_frame(FrameType.ENCRYPTED_DATA, encrypted)
            self._play_audio_bytes(frame)
        else:
            # No encryption — legacy plaintext mode
            self._play_audio_text(message)
    
    def _play_audio_text(self, text: str):
        """Send a plaintext string via ggwave (legacy path)."""
        waveform = ggwave.encode(text, protocolId=self._PROTOCOL_ID, volume=50)
        self._play_waveform(waveform)

    def _play_audio_bytes(self, data: bytes):
        """Send raw bytes via ggwave (base64-encoded, since ggwave expects strings)."""
        encoded = base64.b64encode(data).decode("ascii")
        waveform = ggwave.encode(encoded, protocolId=self._PROTOCOL_ID, volume=50)
        self._play_waveform(waveform)
    
    def _play_waveform(self, waveform):
        """Common audio playback logic."""
        try:
            with suppress_stdout_stderr():
                p = pyaudio.PyAudio()
                stream = p.open(
                    format=pyaudio.paFloat32,
                    channels=1,
                    rate=48000,
                    output=True,
                    output_device_index=self._output_device_index,
                )
            stream.write(waveform, len(waveform) // 4)
            stream.stop_stream()
            stream.close()
            p.terminate()
        except Exception as e:
            print(f"Audio Error: {e}")

    def _generate_id(self):
        # Generates a short 3-character ID like "a9z"
        return ''.join(random.choices(string.ascii_lowercase + string.digits, k=3))

    def _process_queue(self):
        while self.running: # Runs forever until the app closes
            try:
                # GET MESSAGE
                # This line blocks the thread until something arrives in the queue
                # If the queue is empty, the code sits here and does nothing
                message_text = self.msg_queue.get()

                # Generate a unique ID for this specific message
                packet_id = self._generate_id()

                # Format the payload: "ID:MESSAGE"
                full_payload = f"{self.name}:{packet_id}:{message_text}"
                
                # Create a short version for the log (e.g., "Hello wor..." instead of full text)
                display_msg = (message_text[:15] + '...') if len(message_text) > 15 else message_text

                attempts = 0 # Track number of send attempts for this message

                # RETRY LOOP
                while attempts < self.MAX_RETRIES:
                    # IMPORTANT: set expected ACK + clear event BEFORE playback
                    self.current_expected_ack_id = packet_id
                    self.ack_received_event.clear()

                    # Send the ID + message
                    self._transmit(full_payload)

                    # THE WAIT
                    # This pauses execution for up to 6.0 seconds
                    # It returns True immediately if 'notify_ack()' is called
                    # It returns False if 6 seconds pass without a call
                    is_acked = self.ack_received_event.wait(timeout=6.0)

                    if is_acked:
                        if self.on_status_update:
                            self.on_status_update(f"[green]'{display_msg}' Delivered[/green]")
                        break # Exit the 'while attempts' loop, effectively "finishing" this message
                    else:
                        attempts += 1
                        if attempts < self.MAX_RETRIES:
                            if self.on_status_update:
                                self.on_status_update(f"[yellow]No ACK for '{display_msg}'. Retrying...[/yellow]")
                            time.sleep(0.5)
                        else:
                            # Final failure message (max retries reached)
                            if self.on_status_update:
                                self.on_status_update(f"[bold red]Failed to send '{display_msg}'[/bold red]")
                
                # Tells queue that message has been sent, allowing it to move on to the next item
                self.msg_queue.task_done()

            except Exception as e:
                print(f"Sender Error: {e}")