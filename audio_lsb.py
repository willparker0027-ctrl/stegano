import wave
import io
import numpy as np


def _bytes_to_bits(data: bytes):
	for byte in data:
		for i in range(8):
			yield (byte >> (7 - i)) & 1


def _bits_to_bytes(bits):
	b = 0
	count = 0
	for bit in bits:
		b = (b << 1) | bit
		count += 1
		if count == 8:
			yield b
			b = 0
			count = 0


def embed_in_wav(wav_path: str, payload: bytes) -> bytes:
	with wave.open(wav_path, 'rb') as w:
		n_channels = w.getnchannels()
		sampwidth = w.getsampwidth()
		framerate = w.getframerate()
		n_frames = w.getnframes()
		audio_bytes = w.readframes(n_frames)

	if sampwidth != 2:
		raise ValueError('Only 16-bit PCM WAV supported')

	data = (len(payload).to_bytes(4, 'big') + payload)
	samples = np.frombuffer(audio_bytes, dtype=np.int16)
	capacity_bits = samples.size
	needed_bits = len(data) * 8
	if needed_bits > capacity_bits:
		raise ValueError('Payload too large for audio capacity')

	samples = samples.copy()
	bits_iter = _bytes_to_bits(data)
	for i in range(needed_bits):
		bit = next(bits_iter)
		samples[i] = (samples[i] & 0xFFFE) | bit

	out_bytes = samples.tobytes()
	buf = io.BytesIO()
	with wave.open(buf, 'wb') as wout:
		wout.setnchannels(n_channels)
		wout.setsampwidth(sampwidth)
		wout.setframerate(framerate)
		wout.writeframes(out_bytes)
	return buf.getvalue()


def extract_from_wav(wav_path: str) -> bytes:
	with wave.open(wav_path, 'rb') as w:
		sampwidth = w.getsampwidth()
		n_frames = w.getnframes()
		audio_bytes = w.readframes(n_frames)
	if sampwidth != 2:
		raise ValueError('Only 16-bit PCM WAV supported')
	samples = np.frombuffer(audio_bytes, dtype=np.int16)
	bits = samples & 1

	length_bits = bits[:32]
	length = 0
	for bit in length_bits:
		length = (length << 1) | int(bit)
	payload_bits = bits[32:32 + length * 8]
	payload = bytes(_bits_to_bytes(int(b) for b in payload_bits))
	if len(payload) != length:
		raise ValueError('Corrupted or incomplete payload in audio')
	return payload
