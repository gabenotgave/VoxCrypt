import os
from contextlib import contextmanager
import pyaudio
import sounddevice as sd

@contextmanager
def suppress_stdout_stderr():
    """
    A context manager that redirects C-level stdout and stderr to /dev/null
    to prevent library logs from breaking the Textual UI.
    """
    # Open null files
    with open(os.devnull, "w") as devnull:
        # Save the actual stdout (1) and stderr (2) file descriptors.
        old_stdout = os.dup(1)
        old_stderr = os.dup(2)

        try:
            # Redirect stdout and stderr to null
            os.dup2(devnull.fileno(), 1)
            os.dup2(devnull.fileno(), 2)
            yield
        finally:
            # Restore stdout and stderr
            os.dup2(old_stdout, 1)
            os.dup2(old_stderr, 2)
            os.close(old_stdout)
            os.close(old_stderr)

def get_audio_output_devices():
    """
    Returns a list of available audio output devices.
    Each item is a dictionary with:
      - 'index': The ID needed by PyAudio to use this device
      - 'name': The human-readable name (e.g., 'MacBook Pro Speakers')
      - 'channels': Number of output channels
    """
    p = pyaudio.PyAudio()
    devices = []
    
    try:
        # Iterate through all devices (input and output)
        for i in range(p.get_device_count()):
            dev_info = p.get_device_info_by_index(i)
            
            # Check if it has output channels (speakers/headphones)
            if dev_info.get('maxOutputChannels') > 0:
                devices.append({
                    "index": i,
                    "name": dev_info.get('name'),
                    "channels": dev_info.get('maxOutputChannels'),
                    "sample_rate": int(dev_info.get('defaultSampleRate'))
                })
    finally:
        p.terminate()
        
    return devices

def get_audio_input_devices():
    """
    Returns a list of available audio INPUT devices (Microphones).
    """
    p = pyaudio.PyAudio()
    devices = []
    
    try:
        for i in range(p.get_device_count()):
            try:
                dev_info = p.get_device_info_by_index(i)
                # Check if device has INPUT channels
                if dev_info.get('maxInputChannels') > 0:
                    devices.append({
                        "index": i,
                        "name": dev_info.get('name'),
                        "channels": dev_info.get('maxInputChannels'),
                        "sample_rate": int(dev_info.get('defaultSampleRate'))
                    })
            except Exception:
                continue
    finally:
        p.terminate()
        
    return devices