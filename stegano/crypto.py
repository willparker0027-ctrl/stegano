import os
import json
from dataclasses import dataclass
from typing import Tuple

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.backends import default_backend

PBKDF2_ITERS = 200_000
KEY_LEN = 32


def _derive_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=KEY_LEN,
		salt=salt,
		iterations=PBKDF2_ITERS,
		backend=default_backend(),
	)
	return kdf.derive(password.encode('utf-8'))


def encrypt_with_aes(plaintext: bytes, password: str) -> bytes:
	salt = os.urandom(16)
	nonce = os.urandom(12)
	key = _derive_key(password, salt)
	aesgcm = AESGCM(key)
	ct = aesgcm.encrypt(nonce, plaintext, None)
	return json.dumps({'v': 1, 'alg': 'aes-gcm', 'salt': salt.hex(), 'nonce': nonce.hex()}).encode('utf-8') + b'\n' + ct


def decrypt_with_aes(blob: bytes, password: str) -> bytes:
	head_line, ct = blob.split(b'\n', 1)
	head = json.loads(head_line.decode('utf-8'))
	salt = bytes.fromhex(head['salt'])
	nonce = bytes.fromhex(head['nonce'])
	key = _derive_key(password, salt)
	aesgcm = AESGCM(key)
	return aesgcm.decrypt(nonce, ct, None)


# RSA hybrid: generate random AES key, encrypt data with AES-GCM, encrypt AES key with RSA OAEP

def encrypt_with_rsa_public_key(plaintext: bytes, public_pem: str) -> bytes:
	public_key = serialization.load_pem_public_key(public_pem.encode('utf-8'))
	aes_key = os.urandom(KEY_LEN)
	nonce = os.urandom(12)
	aesgcm = AESGCM(aes_key)
	ct = aesgcm.encrypt(nonce, plaintext, None)
	enc_key = public_key.encrypt(
		aes_key,
		padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
	)
	payload = {
		'v': 1,
		'alg': 'rsa-hybrid',
		'nonce': nonce.hex(),
		'enc_key': enc_key.hex(),
	}
	return json.dumps(payload).encode('utf-8') + b'\n' + ct


def decrypt_with_rsa_private_key(blob: bytes, private_pem: str) -> bytes:
	head_line, ct = blob.split(b'\n', 1)
	head = json.loads(head_line.decode('utf-8'))
	private_key = serialization.load_pem_private_key(private_pem.encode('utf-8'), password=None)
	enc_key = bytes.fromhex(head['enc_key'])
	nonce = bytes.fromhex(head['nonce'])
	aes_key = private_key.decrypt(
		enc_key,
		padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
	)
	aesgcm = AESGCM(aes_key)
	return aesgcm.decrypt(nonce, ct, None)
