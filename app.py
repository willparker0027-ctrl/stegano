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
	algo = request.form.get('algo', 'aes')
	password = request.form.get('password') or ''
	rsa_public_pem = request.form.get('rsa_public_pem') or ''

	if not cover:
		return jsonify({'error': 'Cover file is required'}), 400

	cover_filename = secure_filename(cover.filename or f'cover_{secrets.token_hex(4)}')
	cover_path = os.path.join(UPLOAD_DIR, cover_filename)
	cover.save(cover_path)

	if secret_file and secret_file.filename:
		secret_bytes = secret_file.read()
		secret_meta = {'filename': secret_file.filename, 'type': 'file'}
	elif secret_text:
		secret_bytes = secret_text.encode('utf-8')
		secret_meta = {'filename': 'secret.txt', 'type': 'text'}
	else:
		return jsonify({'error': 'Provide a secret text or file'}), 400

	# Encrypt
	if algo == 'rsa' and rsa_public_pem.strip():
		payload = encrypt_with_rsa_public_key(secret_bytes, rsa_public_pem)
	else:
		if not password:
			return jsonify({'error': 'Password is required for AES encryption'}), 400
		payload = encrypt_with_aes(secret_bytes, password)

	head = {
		'version': 1,
		'ts': datetime.utcnow().isoformat() + 'Z',
		'secret_meta': secret_meta,
		'encryption': {'scheme': 'aes-gcm' if algo == 'aes' else 'rsa-hybrid'},
	}
	container = json.dumps(head).encode('utf-8') + b'\n\n' + payload

	media_kind = infer_media_kind(cover_filename)
	stego_name = None
	stego_bytes = None

	try:
		if media_kind == 'image':
			stego_bytes = embed_in_image(cover_path, container)
			stego_name = os.path.splitext(cover_filename)[0] + '_stego.png'
		elif media_kind == 'audio':
			stego_bytes = embed_in_wav(cover_path, container)
			stego_name = os.path.splitext(cover_filename)[0] + '_stego.wav'
		elif media_kind == 'video':
			# For video, save temporarily then read
			stego_path = os.path.join(OUTPUT_DIR, os.path.splitext(cover_filename)[0] + '_stego.avi')
			os.makedirs(OUTPUT_DIR, exist_ok=True)
			embed_in_video(cover_path, container, stego_path)
			stego_name = os.path.basename(stego_path)
			with open(stego_path, 'rb') as f:
				stego_bytes = f.read()
		else:
			return jsonify({'error': 'Unsupported cover file type'}), 400
	except Exception as e:
		return jsonify({'error': f'Embedding failed: {e}'}), 500

	# Save file to outputs directory
	if stego_bytes:
		os.makedirs(OUTPUT_DIR, exist_ok=True)
		stego_path = os.path.join(OUTPUT_DIR, stego_name)
		with open(stego_path, 'wb') as f:
			f.write(stego_bytes)
		
		# Return JSON with download URL
		return jsonify({
			'filename': stego_name,
			'download_url': url_for('download_file', name=stego_name, _external=True)
		})
	else:
		return jsonify({'error': 'Failed to generate stego file'}), 500

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
	# Ensure output directory exists
	os.makedirs(OUTPUT_DIR, exist_ok=True)
	
	# Secure the filename to prevent directory traversal
	secure_name = secure_filename(name)
	path = os.path.join(OUTPUT_DIR, secure_name)
	
	# Log the download attempt for debugging
	print(f"Download request for: {name} -> {secure_name}")
	
	if not os.path.exists(path):
		print(f"File not found: {path}")
		return jsonify({'error': 'File not found. It may have been deleted or never created.'}), 404
	
	try:
		# Get file size and MIME type
		file_size = os.path.getsize(path)
		mime_type, _ = mimetypes.guess_type(path)
		if mime_type is None:
			mime_type = 'application/octet-stream'
		
		print(f"Serving file: {path} (size: {file_size} bytes, type: {mime_type})")
		
		# Create response with proper headers to prevent 206 Partial Content
		response = make_response()
		response.headers['Content-Type'] = mime_type
		response.headers['Content-Disposition'] = f'attachment; filename="{secure_name}"'
		response.headers['Content-Length'] = str(file_size)
		response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
		response.headers['Pragma'] = 'no-cache'
		response.headers['Expires'] = '0'
		response.headers['Accept-Ranges'] = 'none'  # Prevent range requests that cause 206
		response.headers['X-Content-Type-Options'] = 'nosniff'
		response.headers['X-Frame-Options'] = 'DENY'
		
		# Read and send file
		with open(path, 'rb') as f:
			response.data = f.read()
		
		print(f"Successfully prepared download for: {secure_name}")
		return response
	except Exception as e:
		print(f"Download error for {secure_name}: {str(e)}")
		return jsonify({'error': f'Download failed: {str(e)}'}), 500


@app.get('/test-download')
def test_download():
	"""Test endpoint to verify download functionality"""
	test_file_path = os.path.join(OUTPUT_DIR, 'test.txt')
	
	# Create a test file if it doesn't exist
	if not os.path.exists(test_file_path):
		with open(test_file_path, 'w') as f:
			f.write("This is a test file for download functionality.\n")
			f.write("If you can download this file, the download system is working correctly.\n")
	
	return redirect(url_for('download_file', name='test.txt'))


if __name__ == '__main__':
	port = int(os.environ.get('PORT', '5000'))
	
	# Check if running on Render (production) or locally
	if os.environ.get('RENDER'):
		# Running on Render - use HTTP only, Render handles HTTPS
		print("🚀 Starting on Render...")
		print(f"🌐 Running on port: {port}")
		app.run(host='0.0.0.0', port=port, debug=False)
	else:
		# Running locally - can use HTTPS if certificates exist
		ssl_context = None
		if os.path.exists('certs/cert.pem') and os.path.exists('certs/key.pem'):
			ssl_context = ('certs/cert.pem', 'certs/key.pem')
			print("🔒 Starting with HTTPS...")
			print(f"🌐 Access at: https://localhost:{port}")
		else:
			print("⚠️  SSL certificates not found, starting with HTTP...")
			print(f"🌐 Access at: http://localhost:{port}")
		
		app.run(host='0.0.0.0', port=port, debug=True, ssl_context=ssl_context)
