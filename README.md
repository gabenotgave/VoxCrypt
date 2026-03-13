## VoxCrypt
**End‑to‑end encrypted text over sound waves**

[![Python Version](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen.svg)](#)

---

![VoxCrypt Demo](docs/demo.png)

---

## Overview

VoxCrypt is a Python CLI application that turns any pair of speakers and microphones into an end‑to‑end encrypted messaging channel. Instead of TCP sockets or Bluetooth, VoxCrypt uses **ggwave** to encode data into short audio waveforms that can be sent over the air or even through a phone/VoIP call.

On top of this acoustic transport, VoxCrypt layers a modern cryptographic protocol: **X25519 Diffie‑Hellman** key exchange with a **commit‑reveal** pattern, **AES‑256‑GCM** for authenticated encryption, and a human‑verifiable **Short Authentication String (SAS)** to detect active man‑in‑the‑middle (MITM) attacks.

The result is a portable, network‑independent secure channel that works in the same room (including ultrasonic “near‑silent” mode) or remotely over any audio path that can carry the tones (phone, VoIP, conferencing tools, etc.).

---

## Features

- **End‑to‑end encrypted acoustic messaging**  
  Uses AES‑256‑GCM with 256‑bit keys derived from an X25519 Diffie‑Hellman exchange.

- **Modern key exchange with commit‑reveal**  
  X25519 key exchange plus a SHA‑256 commitment to the initiator’s public key to prevent key substitution on noisy acoustic links.

- **SAS voice verification against MITM**  
  Both sides display a 6‑digit Short Authentication String derived from the shared secret. Reading the code aloud (like ZRTP) detects active MITM attacks.

- **Robust delivery with automatic retries & ACKs**  
  Messages are sent with an ID and retried up to a configurable maximum until an authenticated ACK is received.

- **Nonce safety by design**  
  Each retry fully **re‑encrypts** the payload with a fresh AES‑GCM nonce; nonces are never reused for the same key.

- **Base64 framing over ggwave**  
  Binary ciphertext and handshake frames are wrapped in a simple wire format and then base64‑encoded so they can be carried over ggwave’s text‑oriented interface.

- **Three transmission modes**  
  - **Remote** – robust audible profile tuned for phone/VoIP paths.  
  - **Proximity** – fast audible profile for same‑room communication.  
  - **Supersonic** – fastest near‑ultrasonic profile for close‑range devices that can handle higher frequencies.

- **Interactive terminal UI**  
  A Rich‑powered setup wizard walks you through username, speaker, microphone, and mode selection, then drops into a real‑time chat prompt with background receive.

- **Cross‑platform**  
  Built on Python, ggwave, and PyAudio; designed to run on **macOS, Linux, and Windows** (with PortAudio installed).

- **Modular architecture**  
  The `crypto` package is completely independent from the audio transport and UI, making it easy to reuse or test in isolation.

---

## How It Works

### Handshake: Commit‑Reveal + SAS

Two devices perform an authenticated X25519 key exchange over acoustic frames:

```text
Device A (Initiator)                      Device B (Responder)
-----------------------                   ----------------------
Generate (pk_a, sk_a), random_a
commitment = SHA256(pk_a || random_a)
          HANDSHAKE_COMMITMENT (commitment)
------------------------------------------>
                                          Store commitment
                                          Generate (pk_b, sk_b)
                         HANDSHAKE_PK (pk_b)
<------------------------------------------
Derive shared secret from pk_b, sk_a
session_key, SAS_a = KDF(shared_secret)
reveal = pk_a || random_a
          HANDSHAKE_REVEAL (reveal)
------------------------------------------>
                                          Verify SHA256(pk_a || random_a)
                                          matches stored commitment
                                          session_key, SAS_b = KDF(shared_secret)
                                          (Handshake complete if verification OK)
```

Both sides then display a **6‑digit SAS** derived from the shared secret:

- If SAS codes **match** when read aloud, the session key is trusted.
- If they **don’t match**, the app aborts the session as a likely MITM.

### Encrypted Message Flow

Once the session key is established, all chat messages are encrypted and sent over ggwave:

```text
User input text
      |
      v
+----------------+     +-----------------+     +----------------------+
|  AES-256-GCM   | --> |  Frame: type=   | --> |  Base64 encode +     |
| (key from KDF) |     |  ENCRYPTED_DATA |     |  ggwave.encode()     |
+----------------+     +-----------------+     +----------------------+
                                                         |
                                                         v
                                                    Audio waveform
```

On the receiving side:

```text
Audio waveform
      |
      v
ggwave.decode() --> Base64 decode --> Frame decode --> AES-GCM decrypt --> Plaintext
```

ACKs are just lightweight encrypted frames with type `ACK` that echo the message ID back to the sender.

---

## Security Model

### What VoxCrypt Protects Against

- **Passive eavesdroppers** listening to the audio channel cannot read messages:
  - All post‑handshake data uses **AES‑256‑GCM** with keys derived from X25519.
  - The ciphertext, nonce, and authentication tag are all carried inside the encrypted frame.

- **Active MITM on the acoustic path**:
  - The **commit‑reveal** step prevents an attacker from freely choosing keys on both sides unnoticed.
  - The **SAS voice verification** ensures both participants share the same DH output; a MITM cannot fake matching codes without also compromising an endpoint.

- **Ciphertext tampering and frame corruption**:
  - AES‑GCM provides **integrity and authenticity**; invalid tags raise errors and frames are dropped.
  - `framing.py` validates handshake frame sizes and rejects malformed frames.

- **Nonce reuse**:
  - Every encryption call generates a new random nonce.
  - Retries **re‑encrypt** the message from scratch, so the same plaintext is never sent with the same `(key, nonce)` pair.

- **Plaintext injection after handshake**:
  - Once a secure session is active, the receiver **ignores unauthenticated plaintext** frames and only processes properly framed and decrypted messages.

### What VoxCrypt Does Not Protect Against

- **Compromised endpoints**: Malware or an attacker with access to a device can read decrypted messages, capture keys, or tamper with the UI.
- **Side‑channel leaks**: VoxCrypt does not defend against timing attacks, acoustic side‑channels beyond the intentional waveform, or OS‑level logging of audio.
- **Metadata**: Observers can still tell *that* two devices are communicating and roughly *when* messages are sent (from the tones), even if they cannot read the content.
- **Replay of valid ciphertext by a peer with the key**: The current design deduplicates only the last message ID across the session. A malicious peer (already in possession of the session key) could replay older messages.

---

## Getting Started

### Prerequisites

- **Python**: 3.10 or newer.
- **PortAudio** (for PyAudio):
  - macOS: `brew install portaudio`
  - Ubuntu/Debian: `sudo apt-get install portaudio19-dev`
  - Windows: install via the official PortAudio binaries or ensure your Python/PyAudio wheel bundles it.
- Working speakers and microphone on each device (or a phone/VoIP app to carry audio between devices).

### Installation

```bash
# Clone the repository
git clone https://github.com/gabenotgave/VoxCrypt.git
cd VoxCrypt

# Create and activate a virtual environment (recommended)
python -m venv .venv
source .venv/bin/activate      # On Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the App

On **each device** (or terminal instance):

```bash
python VoxCryptApp.py
```

You’ll see a Rich‑styled banner and then enter the setup wizard.

---

## Usage

### 1. Setup Wizard

On startup, VoxCrypt walks you through:

1. **Username**  
   Choose a display name for this device (e.g. “Alice”, “Bob”).

2. **Speaker (Output) Device**  
   Select the audio output from a numbered list (e.g. laptop speakers, headphones).

3. **Microphone (Input) Device**  
   Select the microphone to capture incoming waveforms.

4. **Transmission Mode**  
   - `1` – **Remote (Phone/VoIP)**: most robust, slower audible tones tuned for compressed channels.  
   - `2` – **Proximity (Local)**: fast audible mode for same‑room devices.  
   - `3` – **Supersonic (Local)**: near‑ultrasonic fastest mode; may require decent speakers/mics and quiet environments.

After configuration, the app shows a **Configuration Summary** panel and switches to “SYSTEM ONLINE”.

### 2. Key Exchange (Handshake)

For **remote mode**, VoxCrypt automatically runs the acoustic handshake:

1. Both sides see a **KEY EXCHANGE** section.
2. One side presses `I` to initiate; the other waits and will detect the incoming commitment.
3. Frames for commitment, `pk_b`, and reveal are exchanged over audio.
4. Both sides derive the same AES‑256 key and display a **6‑digit verification code**.
5. Read the code aloud and confirm:
   - Type `y` if codes match → session established.
   - Type `n` if they differ → session is aborted as potential MITM.

For proximity/supersonic modes, the same handshake runs over a more aggressive acoustic profile.

### 3. Chat Session

Once the handshake completes:

- You see a prompt like `Alice>`.
- Type a message and hit **Enter**:
  - The app prints your message locally.
  - It encrypts the payload, frames it, base64‑encodes it, and plays the waveform through the speaker.
  - The receiver on the other side decodes, decrypts, and prints it with the sender name.

The sender automatically retries if no ACK is received, and shows status messages such as:

- `'<hello>' Delivered`
- `No ACK for '<hello>'. Retrying...`
- `Failed to send '<hello>'`

Press **Ctrl‑C** or **Ctrl‑D** to exit.

---

## Running Tests

From the project root, with your virtual environment active:

```bash
python -m pytest tests/ -v
```

This runs the unit tests for symmetric crypto, key exchange, framing, and handshake orchestration.

---

## Project Structure

```text
VoxCrypt/
├── crypto/
│   ├── __init__.py
│   ├── symmetric.py          # AES-256-GCM encrypt/decrypt helpers
│   ├── keyexchange.py        # X25519 + commitment + SAS derivation
│   ├── framing.py            # Wire format encoding/decoding for frames
│   └── errors.py             # Custom exception hierarchy for crypto
├── transport/
│   ├── __init__.py
│   └── handshake.py          # Handshake coordinator (bridges crypto & transport)
├── tests/
│   ├── __init__.py
│   ├── test_symmetric.py     # AES-GCM tests
│   ├── test_keyexchange.py   # X25519 + SAS tests
│   ├── test_framing.py       # Frame encode/decode tests
│   └── test_handshake.py     # Handshake coordinator tests
├── Sender.py                 # Message sending, retry loop, ACK handling
├── Receiver.py               # Audio capture, ggwave decode, frame routing
├── VoxCryptApp.py            # Main CLI app and Rich-based UI
├── utils.py                  # Audio device enumeration, stdout/stderr suppression
├── pyproject.toml            # Build/packaging metadata
└── requirements.txt          # Python dependencies
```

---

## Configuration: Transmission Modes

VoxCrypt currently supports three acoustic profiles (via ggwave protocol IDs):

- **Remote (Phone/VoIP)**  
  - Uses a more conservative audible protocol tuned for lossy, band‑limited channels like phone calls or VoIP.
  - Best for long‑distance communication where reliability matters more than speed.

- **Proximity (Local)**  
  - Uses the fastest audible profile for nearby devices in the same room.
  - Suitable when users can hear (and tolerate) brief chirps.

- **Supersonic (Local)**  
  - Uses a near‑ultrasonic protocol aimed at capable laptop/phone speakers and microphones.
  - Provides the fastest throughput but may be less reliable on low‑quality audio hardware and is more sensitive to positioning and noise.

You select the mode during the setup wizard; it controls which ggwave protocol profile is used for both handshake and encrypted messages.

---

## Roadmap

- [ ] Encrypted keystore for long‑term key storage (at‑rest protection)  
- [ ] Stronger replay protection (nonce‑seen or message‑ID cache per session)  
- [ ] Key expiration and rotation logic for long‑running sessions  
- [ ] GUI frontend (desktop or web‑based) on top of the existing core  
- [ ] Pre‑shared key mode for proximity (e.g., QR‑code pairing instead of acoustic handshake)

---

## Contributing

Contributions, bug reports, and feature requests are welcome.

1. **Fork** the repository on GitHub.
2. **Create a feature branch**:

   ```bash
   git checkout -b feature/my-awesome-change
   ```

3. **Make your changes** and add or update tests where appropriate.
4. **Run the test suite**:

   ```bash
   pytest tests/ -v
   ```

5. **Open a Pull Request** describing your changes, rationale, and any trade‑offs.

Please keep changes focused, documented, and consistent with the existing coding style.

---

## License

VoxCrypt is released under the **MIT License**.

```text
MIT License

Copyright (c) 2026 <Your Name>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```
