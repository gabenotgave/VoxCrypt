import os
import sys
import select
import termios
import tty
import threading
from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from Sender import Sender
from Receiver import Receiver
from utils import get_audio_input_devices, get_audio_output_devices
from transport.handshake import HandshakeCoordinator
import time

# ── Constants ────────────────────────────────────────────────────────
VERSION = "1.0.0"

BANNER = """\
██╗   ██╗ ██████╗ ██╗  ██╗ ██████╗██████╗ ██╗   ██╗██████╗ ████████╗
██║   ██║██╔═══██╗╚██╗██╔╝██╔════╝██╔══██╗╚██╗ ██╔╝██╔══██╗╚══██╔══╝
██║   ██║██║   ██║ ╚███╔╝ ██║     ██████╔╝ ╚████╔╝ ██████╔╝   ██║   
╚██╗ ██╔╝██║   ██║ ██╔██╗ ██║     ██╔══██╗  ╚██╔╝  ██╔═══╝    ██║   
 ╚████╔╝ ╚██████╔╝██╔╝ ██╗╚██████╗██║  ██║   ██║   ██║        ██║   
  ╚═══╝   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝   ╚═╝   ╚═╝        ╚═╝   
   S E C U R E   C O M M U N I C A T I O N   P R O T O C O L"""

console = Console()

# Single lock for ALL terminal writes (Rich + raw stdout)
_term_lock = threading.Lock()


class InputState:
    def __init__(self, prompt_str: str, input_buf: list[str]):
        self.prompt_str = prompt_str
        self.input_buf = input_buf

_input_state: InputState | None = None

# ── Helpers ──────────────────────────────────────────────────────────

def _redraw_prompt(locked: bool = False) -> None:
    if not _input_state:
        return
    if not locked:
        with _term_lock:
            sys.stdout.write(f"\r\033[2K{_input_state.prompt_str}{''.join(_input_state.input_buf)}")
            sys.stdout.flush()
    else:
        sys.stdout.write(f"\r\033[2K{_input_state.prompt_str}{''.join(_input_state.input_buf)}")
        sys.stdout.flush()

def safe_print(message: str) -> None:
    """Print from any thread without losing the prompt."""
    with _term_lock:
        sys.stdout.write("\r\033[2K")
        sys.stdout.flush()
        console.print(message)
        _redraw_prompt(locked=True)

def clear_screen() -> None:
    """Clear the terminal (including scrollback) and reprint the banner."""
    # \033[2J clears the visible screen, \033[3J clears the scrollback buffer,
    # \033[H moves the cursor to top-left.
    sys.stdout.write("\033[2J\033[3J\033[H")
    sys.stdout.flush()
    with _term_lock:
        console.print(f"[bold #007acc]{BANNER}[/]")
        console.print(f"\n[dim]v{VERSION}[/dim]\n")

def prompt(label: str) -> str:
    """Display a cyan prompt and return stripped input."""
    with _term_lock:
        return console.input(f"[bold cyan]{label}[/bold cyan] ").strip()

# ── Setup wizard steps ───────────────────────────────────────────────

def ask_username() -> str:
    """Step 1 - Ask for a username."""
    clear_screen()
    with _term_lock:
        console.print("[bold cyan]STEP 1 · SET USERNAME[/bold cyan]\n")
    while True:
        val = prompt("Enter username:")
        if val:
            with _term_lock:
                console.print(f"[yellow]Username set: {val}[/yellow]")
            return val
        with _term_lock:
            console.print("[red]Username cannot be empty. Try again.[/red]")

def ask_output_device() -> tuple[int, str]:
    """Step 2 - Select an audio output (speaker) device."""
    clear_screen()
    with _term_lock:
        console.print("[bold cyan]STEP 2 · SELECT SPEAKER (OUTPUT)[/bold cyan]\n")
    devices = get_audio_output_devices()
    valid_indices = {d["index"] for d in devices}

    with _term_lock:
        for dev in devices:
            console.print(f"  [bold][{dev['index']}][/bold] {dev['name']}")
        console.print()

    while True:
        val = prompt("Enter speaker index:")
        if val.isdigit() and int(val) in valid_indices:
            idx = int(val)
            name = next(d["name"] for d in devices if d["index"] == idx)
            with _term_lock:
                console.print(f"[yellow]Speaker set to: {name}[/yellow]")
            return idx, name
        with _term_lock:
            console.print(f"[red]Invalid speaker index '{val}'. Try again.[/red]")

def ask_input_device() -> tuple[int, str]:
    """Step 3 – Select an audio input (microphone) device."""
    clear_screen()
    with _term_lock:
        console.print("[bold cyan]STEP 3 · SELECT MICROPHONE (INPUT)[/bold cyan]\n")
    devices = get_audio_input_devices()
    valid_indices = {d["index"] for d in devices}

    with _term_lock:
        for dev in devices:
            console.print(f"  [bold][{dev['index']}][/bold] {dev['name']}")
        console.print()

    while True:
        val = prompt("Enter mic index:")
        if val.isdigit() and int(val) in valid_indices:
            idx = int(val)
            name = next(d["name"] for d in devices if d["index"] == idx)
            with _term_lock:
                console.print(f"[yellow]Microphone set to: {name}[/yellow]")
            return idx, name
        with _term_lock:
            console.print(f"[red]Invalid mic index '{val}'. Try again.[/red]")

def ask_protocol() -> tuple[int, str]:
    """Step 4 – Select transmission protocol."""
    clear_screen()
    with _term_lock:
        console.print("[bold cyan]STEP 4 · SELECT TRANSMISSION MODE[/bold cyan]\n")
        console.print("  [bold][1][/bold] Remote (Phone Call / VoIP)   – [italic]Robust, audible[/italic]")
        console.print("  [bold][2][/bold] Proximity (Same Room)        – [italic]Fast, audible[/italic]")
        console.print("  [bold][3][/bold] Supersonic (Same Room)       – [italic]Fastest, near-ultrasonic[/italic]")
        console.print()

    while True:
        val = prompt("Enter 1, 2, or 3:")
        if val == "1":
            with _term_lock:
                console.print("[yellow]Mode set: REMOTE (PHONE)[/yellow]")
            # ggwave: 0 = Normal (audible, most robust)
            return 0, "REMOTE (PHONE)"
        elif val == "2":
            with _term_lock:
                console.print("[yellow]Mode set: PROXIMITY (LOCAL)[/yellow]")
            # ggwave: 2 = Fastest audible profile
            return 2, "PROXIMITY (LOCAL)"
        elif val == "3":
            with _term_lock:
                console.print("[yellow]Mode set: SUPERSONIC (LOCAL)[/yellow]")
            # ggwave: 5 = [U] Fastest (near-ultrasonic, hardware-dependent)
            return 5, "SUPERSONIC (LOCAL)"
        with _term_lock:
            console.print("[red]Invalid selection. Please type 1, 2, or 3.[/red]")

def show_summary(username: str, speaker_name: str, mic_name: str, mode_name: str) -> None:
    """Display a configuration summary panel."""
    clear_screen()
    summary = Text()
    summary.append("Username:          ", style="bold")
    summary.append(f"{username}\n")
    summary.append("Output Device:     ", style="bold")
    summary.append(f"{speaker_name}\n")
    summary.append("Input Device:      ", style="bold")
    summary.append(f"{mic_name}\n")
    summary.append("Transmission Mode: ", style="bold")
    summary.append(f"{mode_name}")

    with _term_lock:
        console.print(Panel(summary, title="[bold]Configuration Summary[/bold]", border_style="cyan"))
        console.print()
        console.print("[bold green]SYSTEM ONLINE.[/bold green]\n")

# ── Packet handling ───────────────────

class PacketHandler:
    """
    Processes decoded packets from the Receiver callback.
    Runs from a background thread - uses safe_print for clean prompt redraw.
    """

    def __init__(self, username: str, sender: Sender):
        self.username = username
        self.sender = sender
        self.last_received_id: str | None = None

    def handle(self, raw_data: str) -> None:
        """Entry point called by the Receiver thread."""
        # ACKs
        if raw_data.startswith("ACK:"):
            ack_id = raw_data[4:]
            if self.sender and self.sender.current_expected_ack_id == ack_id:
                self.sender.notify_ack()
            return

        # Ignore own echo
        if raw_data.startswith(f"{self.username}:"):
            return

        # Parse "username:packet_id:content"
        parts = raw_data.split(":", 2)
        if len(parts) != 3 or not all(parts):
            return

        sender_name, msg_id, content = parts

        # Duplicate check
        if msg_id == self.last_received_id:
            if self.sender:
                self.sender.send_ack(msg_id)
            return

        # New message
        self.last_received_id = msg_id
        if self.sender:
            self.sender.send_ack(msg_id)

        # Print safely
        safe_print(f"[bold magenta]{sender_name}:[/bold magenta] {content}")

# ── Sender status callback ──────────────────────────────────────────

def handle_sender_status(status_msg: str) -> None:
    """Called from the Sender background thread to display status updates."""
    safe_print(f"[dim italic]{status_msg}[/dim italic]")

# ── Main ─────────────────────────────────────────────────────────────

def main() -> None:
    # ---- Setup Wizard ----
    username = ask_username()
    output_idx, speaker_name = ask_output_device()
    input_idx, mic_name = ask_input_device()
    protocol_id, mode_name = ask_protocol()

    show_summary(username, speaker_name, mic_name, mode_name)

    # ---- Initialize Sender & Receiver ----
    sender = Sender(
        name=username,
        protocol_id=protocol_id,
        output_device_index=output_idx,
        on_status_update=handle_sender_status,
        session_key=None
    )

    session_key = perform_handshake(sender, input_idx)
    if session_key is None:
        safe_print("[bold red]Key exchange failed. Exiting.[/bold red]")
        return
    sender.session_key = session_key

    handler = PacketHandler(username, sender)

    receiver = Receiver(
        input_device_index=input_idx,
        on_message_received=handler.handle,
        session_key=session_key
    )

    # Chat Loop (cbreak mode for clean background output)
    prompt_str = f"{username}> "
    input_buf: list[str] = []  # characters the user has typed so far
    fd = sys.stdin.fileno()
    old_term = termios.tcgetattr(fd)

    global _input_state
    _input_state = InputState(prompt_str, input_buf)

    try:
        tty.setcbreak(fd)  # no echo, char-by-char reads, signals still work
        _redraw_prompt()

        while True:
            ready, _, _ = select.select([fd], [], [], 0.05)

            if not ready:
                continue

            raw = os.read(fd, 1)
            if not raw:             # fd closed
                break
            ch = raw.decode("utf-8", errors="ignore")

            if ch == "\x03":        # Ctrl-C
                raise KeyboardInterrupt
            elif ch == "\x04":      # Ctrl-D  (EOF)
                break
            elif ch in ("\r", "\n"):  # Enter
                msg = "".join(input_buf).strip()
                input_buf.clear()
                if msg:
                    safe_print(f"[bold blue]{username}:[/bold blue] {msg}")
                    sender.send_message(msg)
                _redraw_prompt()
            elif ch in ("\x7f", "\b"):  # Backspace / Delete
                if input_buf:
                    input_buf.pop()
                    _redraw_prompt()
            elif ch == "\x1b":      # Escape sequence (arrow keys etc.) – consume & ignore
                while select.select([fd], [], [], 0.02)[0]:
                    os.read(fd, 1)
            elif ch.isprintable():
                input_buf.append(ch)
                _redraw_prompt()

    except KeyboardInterrupt:
        pass
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_term)
        receiver.stop()
        safe_print("\n[dim]VoxCrypt terminated.[/dim]")

def perform_handshake(sender: Sender, input_device_index: int) -> bytes | None:
    """
    Block until key exchange completes or times out.
    Returns session_key on success, None on failure.
    """
    result = {"key": None, "sas": None}
    handshake_done = threading.Event()

    def on_complete(session_key, sas):
        result["key"] = session_key
        result["sas"] = sas
        handshake_done.set()

    def on_fail(reason):
        safe_print(f"[bold red]{reason}[/bold red]")
        handshake_done.set()

    coordinator = HandshakeCoordinator(
        sender,
        on_complete=on_complete,
        on_fail=on_fail
    )

    # Start a temporary receiver just for the handshake
    handshake_receiver = Receiver(
        input_device_index=input_device_index,
        on_message_received=None,
        on_handshake_frame=coordinator.handle_frame,
        session_key=None,
    )

    with _term_lock:
        console.print("\n[bold cyan]KEY EXCHANGE[/bold cyan]")
        console.print("[dim]Waiting for other device...[/dim]")
        console.print("[dim]Press [bold]I[/bold] to initiate, or wait to respond.[/dim]\n")

    # Wait for user to press 'I' or for incoming commitment
    fd = sys.stdin.fileno()
    old_term = termios.tcgetattr(fd)

    try:
        tty.setcbreak(fd)
        deadline = time.time() + 60  # 60 second timeout
        role_announced = False

        while not handshake_done.is_set() and time.time() < deadline:
            ready, _, _ = select.select([fd], [], [], 0.1)

            # If we've passively become the responder (because we've received
            # a commitment from the other side), update the UI so the user
            # knows they are now just waiting and can no longer initiate.
            if not role_announced and coordinator.role == "responder":
                role_announced = True
                with _term_lock:
                    console.print(
                        "[dim]Handshake commitment received from the other device.[/dim]"
                    )
                    console.print(
                        "[dim]Waiting for key exchange to complete…[/dim]\n"
                    )

            if ready:
                ch = os.read(fd, 1).decode("utf-8", errors="ignore").lower()
                if ch == "i" and coordinator.role is None:
                    coordinator.start_as_initiator()
                elif ch == "\x03":  # Ctrl-C
                    raise KeyboardInterrupt

    except KeyboardInterrupt:
        handshake_receiver.stop()
        return None
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old_term)

    handshake_receiver.stop()

    if result["key"] is None:
        return None

    # ── SAS Verification ──
    with _term_lock:
        console.print(f"\n[bold yellow]🔒 Verification Code: {result['sas']}[/bold yellow]")
        console.print("[dim]Read this code aloud to your partner.[/dim]")
        console.print("[dim]Do they see the same code?[/dim]\n")

    while True:
        val = prompt("Codes match? (y/n):")
        if val.lower() == "y":
            safe_print("[bold green]✅ Identity verified. Session secured.[/bold green]\n")
            return result["key"]
        elif val.lower() == "n":
            safe_print("[bold red]❌ Codes don't match — possible MITM attack. Aborting.[/bold red]")
            return None

if __name__ == "__main__":
    main()