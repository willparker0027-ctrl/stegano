import os
import io
import json
import secrets
import mimetypes
from datetime import datetime
from flask import Flask, render_template, request, send_file, redirect, url_for, jsonify, make_response
from werkzeug.utils import secure_filename

from stegano.crypto import encrypt_with_aes, decrypt_with_aes, encrypt_with_rsa_public_key, decrypt_with_rsa_private_key
from stegano.image_lsb import embed_in_image, extract_from_image
from stegano.audio_lsb import embed_in_wav, extract_from_wav
from stegano.video_lsb import embed_in_video, extract_from_video

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, 'uploads')
OUTPUT_DIR = os.path.join(BASE_DIR, 'outputs')
TEMP_DIR = os.path.join(BASE_DIR, 'temp')

for d in [UPLOAD_DIR, OUTPUT_DIR, TEMP_DIR]:
	os.makedirs(d, exist_ok=True)

ALLOWED_COVER_EXTS = {'.png', '.bmp', '.wav', '.mp3', '.mp4', '.avi', '.mov', '.mkv', '.jpg', '.jpeg'}
ALLOWED_SECRET_EXTS = None  # accept any

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024 * 1024 * 2  # 2 GB


def infer_media_kind(filename: str) -> str:
	name = filename.lower()
	if name.endswith(('.png', '.bmp', '.jpg', '.jpeg')):
		return 'image'
	if name.endswith(('.wav',)):
		return 'audio'
	if name.endswith(('.mp4', '.avi', '.mov', '.mkv')):
		return 'video'
	return 'unknown'


@app.route('/')
def index():
	# Redirect to main app instead of login
	response = redirect(url_for('main_app'))
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Pragma'] = 'no-cache'
	response.headers['Expires'] = '0'
	return response


@app.route('/login')
def login():
	response = make_response(render_template('login.html'))
	response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
	response.headers['Pragma'] = 'no-cache'
	response.headers['Expires'] = '0'
	return response


@app.route('/app')
def main_app():
	# Login check removed - direct access to app
	return render_template('index.html')


@app.route('/extract')
def extract_view():
	# Check if user is logged in using localStorage in the frontend
	# The server will render the template and client-side JS will handle authentication
	return render_template('extract.html')


@app.post('/api/embed')
def api_embed():
	cover = request.files.get('cover')
	secret_file = request.files.get('secret')
	secret_text = request.form.get('secret_text', '')
	algo = request.form.get('algo', 'aes')  # 'aes' or 'rsa'
	password = request.form.get('password') or ''
	rsa_public_pem = request.form.get('rsa_public_pem') or ''

	if not cover:
		return jsonify({'error': 'Cover file is required'}), 400

	cover_filename = secure_filename(cover.filename or f'cover_{secrets.token_hex(4)}')
	cover_path = os.path.join(UPLOAD_DIR, cover_filename)
	cover.save(cover_path)

	if secret_file and secret_file.filename:
		secret_filename = secure_filename(secret_file.filename)
		secret_bytes = secret_file.read()
		secret_meta = {'filename': secret_filename, 'type': 'file'}
	elif secret_text:
		secret_bytes = secret_text.encode('utf-8')
		secret_meta = {'filename': 'secret.txt', 'type': 'text'}
	else:
		return jsonify({'error': 'Provide a secret text or file'}), 400

	# Encrypt
	if algo == 'rsa' and rsa_public_pem.strip():
		payload = encrypt_with_rsa_public_key(secret_bytes, rsa_public_pem)
		enc_meta = {'scheme': 'rsa-hybrid'}
	else:
		if not password:
			return jsonify({'error': 'Password is required for AES encryption'}), 400
		payload = encrypt_with_aes(secret_bytes, password)
		enc_meta = {'scheme': 'aes-gcm'}

	head = {
		'version': 1,
		'ts': datetime.utcnow().isoformat() + 'Z',
		'secret_meta': secret_meta,
		'encryption': enc_meta,
	}
	container = json.dumps(head).encode('utf-8') + b'\n\n' + payload

	media_kind = infer_media_kind(cover_filename)
	stego_name = None
	stego_bytes = None
	stego_path = None

	try:
		if media_kind == 'image':
			stego_bytes = embed_in_image(cover_path, container)
			stego_name = os.path.splitext(cover_filename)[0] + '_stego.png'
			stego_path = os.path.join(OUTPUT_DIR, stego_name)
			with open(stego_path, 'wb') as f:
				f.write(stego_bytes)
		elif media_kind == 'audio':
			stego_bytes = embed_in_wav(cover_path, container)
			stego_name = os.path.splitext(cover_filename)[0] + '_stego.wav'
			stego_path = os.path.join(OUTPUT_DIR, stego_name)
			with open(stego_path, 'wb') as f:
				f.write(stego_bytes)
		elif media_kind == 'video':
			# Prefer AVI container to reduce lossy compression issues that break LSBs
			stego_path = os.path.join(OUTPUT_DIR, os.path.splitext(cover_filename)[0] + '_stego.avi')
			embed_in_video(cover_path, container, stego_path)
			stego_name = os.path.basename(stego_path)
		else:
			return jsonify({'error': 'Unsupported cover file type'}), 400
	except Exception as e:
		return jsonify({'error': f'Embedding failed: {e}'}), 500

	return jsonify({
		'filename': stego_name,
		'download_url': url_for('download_file', name=stego_name, _external=True)
	})


@app.post('/api/extract')
def api_extract():
	stego = request.files.get('stego')
	password = request.form.get('password') or ''
	rsa_private_pem = request.form.get('rsa_private_pem') or ''

	if not stego:
		return jsonify({'error': 'Stego file is required'}), 400

	stego_filename = secure_filename(stego.filename or f'stego_{secrets.token_hex(4)}')
	stego_path = os.path.join(UPLOAD_DIR, stego_filename)
	stego.save(stego_path)

	media_kind = infer_media_kind(stego_filename)

	try:
		if media_kind == 'image':
			container = extract_from_image(stego_path)
		elif media_kind == 'audio':
			container = extract_from_wav(stego_path)
		elif media_kind == 'video':
			container = extract_from_video(stego_path)
		else:
			return jsonify({'error': 'Unsupported stego file type'}), 400
	except Exception as e:
		return jsonify({'error': f'Extraction failed: {e}'}), 500

	try:
		# Validate container format before splitting to provide clearer errors
		if b'\n\n' not in container:
			return jsonify({'error': 'No embedded payload found in the provided file. Make sure you uploaded a stego file generated by this app.'}), 400
		head_raw, payload = container.split(b'\n\n', 1)
		head = json.loads(head_raw.decode('utf-8'))
		scheme = head.get('encryption', {}).get('scheme')
		if scheme == 'rsa-hybrid':
			if not rsa_private_pem.strip():
				return jsonify({'error': 'RSA private key is required for RSA-encrypted payloads'}), 400
			plaintext = decrypt_with_rsa_private_key(payload, rsa_private_pem)
		else:
			if not password:
				return jsonify({'error': 'Password is required for AES decryption'}), 400
			plaintext = decrypt_with_aes(payload, password)
		filename = head.get('secret_meta', {}).get('filename', 'secret.bin')
	except Exception as e:
		return jsonify({'error': f'Decryption failed: {e}'}), 400

	return send_file(
		io.BytesIO(plaintext),
		as_attachment=True,
		download_name=filename
	)


@app.get('/download/<path:name>')
def download_file(name: str):
	path = os.path.join(OUTPUT_DIR, secure_filename(name))
	if not os.path.exists(path):
		return 'Not found', 404
	return send_file(path, as_attachment=True)


if __name__ == '__main__':
	port = int(os.environ.get('PORT', '5000'))
	ssl_context = None
	
	# Check if SSL certificates exist
	if os.path.exists('certs/cert.pem') and os.path.exists('certs/key.pem'):
		ssl_context = ('certs/cert.pem', 'certs/key.pem')
		print("🔒 Starting with HTTPS...")
		print(f"🌐 Access at: https://localhost:{port}")
		print(f"🌐 Network access: https://192.168.1.37:{port}")
		print("")
		print("📝 IMPORTANT: Your browser will show a security warning because we're using")
		print("   self-signed certificates. This is normal for development.")
		print("   Click 'Advanced' and 'Proceed to localhost' to access the app.")
		print("")
	else:
		print("⚠️  SSL certificates not found, starting with HTTP...")
		print(f"🌐 Access at: http://localhost:{port}")
	
	try:
		app.run(host='0.0.0.0', port=port, debug=True, ssl_context=ssl_context)
	except OSError as e:
		if "Address already in use" in str(e):
			print(f"❌ Port {port} is already in use!")
			print("   Please run 'python start_app.py' instead for automatic port management.")
		else:
			raise
