from typing import Tuple
from PIL import Image
import io


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


def embed_in_image(image_path: str, payload: bytes) -> bytes:
	img = Image.open(image_path).convert('RGB')
	pixels = list(img.getdata())
	width, height = img.size
	capacity_bits = width * height * 3
	payload_len = len(payload)
	head = payload_len.to_bytes(4, 'big')
	data = head + payload
	needed_bits = len(data) * 8
	if needed_bits > capacity_bits:
		raise ValueError('Payload too large for image capacity')

	bits_iter = _bytes_to_bits(data)
	new_pixels = []
	for r, g, b in pixels:
		try:
			r = (r & 0xFE) | next(bits_iter)
			g = (g & 0xFE) | next(bits_iter)
			b = (b & 0xFE) | next(bits_iter)
		except StopIteration:
			new_pixels.append((r, g, b))
			break
		new_pixels.append((r, g, b))

	# Fill remaining pixels unchanged
	if len(new_pixels) < len(pixels):
		new_pixels.extend(pixels[len(new_pixels):])

	out = Image.new('RGB', (width, height))
	out.putdata(new_pixels)
	buf = io.BytesIO()
	out.save(buf, format='PNG')
	return buf.getvalue()


def extract_from_image(image_path: str) -> bytes:
	img = Image.open(image_path).convert('RGB')
	pixels = list(img.getdata())
	bits = []
	for r, g, b in pixels:
		bits.extend([r & 1, g & 1, b & 1])

	# First 32 bits is length
	length_bits = bits[:32]
	length = 0
	for bit in length_bits:
		length = (length << 1) | bit

	payload_bits = bits[32:32 + length * 8]
	payload = bytes(_bits_to_bytes(payload_bits))
	if len(payload) != length:
		raise ValueError('Corrupted or incomplete payload in image')
	return payload
