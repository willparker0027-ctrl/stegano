import cv2
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


def _open_writer(output_path: str, fps: float, width: int, height: int):
	"""Try multiple codecs favoring lossless/near-lossless to preserve LSBs."""
	# Prefer FFV1/HuffYUV/Lagarith/MJPG; fallback to mp4v
	tried = []
	for name in ['FFV1', 'HFYU', 'LAGS', 'MJPG', 'mp4v']:
		fourcc = cv2.VideoWriter_fourcc(*name)
		out = cv2.VideoWriter(output_path, fourcc, fps, (width, height))
		tried.append(name)
		if out.isOpened():
			return out
	raise ValueError(f"Unable to open VideoWriter for '{output_path}'. Tried: {', '.join(tried)}")


def embed_in_video(video_path: str, payload: bytes, output_path: str) -> None:
	cap = cv2.VideoCapture(video_path)
	if not cap.isOpened():
		raise ValueError('Cannot open video')

	fps = cap.get(cv2.CAP_PROP_FPS) or 25.0
	width = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
	height = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
	out = _open_writer(output_path, fps, width, height)

	ok, frame = cap.read()
	if not ok:
		cap.release()
		out.release()
		raise ValueError('Empty video')

	# Embed into the first frame using 1 LSB across channels
	head = len(payload).to_bytes(4, 'big')
	data = head + payload
	needed_bits = len(data) * 8
	capacity_bits = width * height * 3
	if needed_bits > capacity_bits:
		cap.release()
		out.release()
		raise ValueError('Payload too large for first frame capacity')

	bits = list(_bytes_to_bits(data))
	flat = frame.reshape(-1, 3)
	for i in range(needed_bits):
		channel = i % 3
		pixel_index = i // 3
		flat[pixel_index, channel] = (flat[pixel_index, channel] & 0xFE) | bits[i]
	frame_embedded = flat.reshape(frame.shape)

	out.write(frame_embedded)
	while True:
		ok, frame = cap.read()
		if not ok:
			break
		out.write(frame)

	cap.release()
	out.release()


def extract_from_video(video_path: str) -> bytes:
	cap = cv2.VideoCapture(video_path)
	if not cap.isOpened():
		raise ValueError('Cannot open video')
	ok, frame = cap.read()
	cap.release()
	if not ok:
		raise ValueError('Empty video')

	flat = frame.reshape(-1, 3)
	bits = []
	for px in flat:
		bits.extend([int(px[0] & 1), int(px[1] & 1), int(px[2] & 1)])

	length_bits = bits[:32]
	length = 0
	for bit in length_bits:
		length = (length << 1) | bit
	
	# Ensure we have enough bits for the payload; if not, data is corrupted
	if 32 + length * 8 > len(bits):
		raise ValueError('Embedded data appears corrupted or truncated in the first frame')
	
	payload_bits = bits[32:32 + length * 8]
	payload_bytes = list(_bits_to_bytes(payload_bits))
	
	# Make sure we have the expected number of bytes
	if len(payload_bytes) < length:
		raise ValueError('Embedded data appears corrupted or altered by compression')
	
	payload = bytes(payload_bytes)
	return payload
