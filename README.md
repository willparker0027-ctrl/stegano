# Stegano

Dual-layer security: AES/RSA encryption + steganography for Image, Audio, and Video.

## Setup

1. Create a virtual env and install deps:

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

2. Run:

```
python app.py
```

Open http://localhost:5000

## Features
- AES-GCM with PBKDF2 password derivation
- RSA hybrid (encrypt AES key with RSA OAEP)
- Image LSB (PNG/JPG input → PNG output)
- Audio LSB for 16-bit PCM WAV
- Video frame-based LSB (first frame) with OpenCV
- Drag-and-drop UI with one-click sharing (Email, WhatsApp, Telegram)

## Notes
- Audio: only WAV (16-bit PCM) is supported for embedding.
- Video: payload capacity limited by first frame size.
- Large media files may take time to process.
