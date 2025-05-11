from flask import Flask, render_template, request, send_from_directory, flash, redirect, url_for
import os
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
app = Flask(__name__)
app.secret_key = "your_secret_key"  # Change this to a secure key in production

# Directories for file storage
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

def pad(data):
    """Apply PKCS7 padding."""
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    """Remove PKCS7 padding."""
    pad_len = data[-1]
    return data[:-pad_len]

def encrypt_file(input_filepath, output_filepath, password):
    """Encrypt a file using AES encryption."""
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(input_filepath, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)

    with open(output_filepath, 'wb') as f:
        f.write(salt + cipher.iv + ciphertext)

def decrypt_file(input_filepath, output_filepath, password):
    """Decrypt an AES-encrypted file."""
    with open(input_filepath, 'rb') as f:
        file_data = f.read()

    salt, iv, ciphertext = file_data[:16], file_data[16:32], file_data[32:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(output_filepath, 'wb') as f:
        f.write(plaintext)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files or request.files['file'].filename == '':
        flash("No file selected")
        return redirect(url_for('index'))

    password = request.form.get('password')
    if not password:
        flash("Password is required for encryption")
        return redirect(url_for('index'))

    file = request.files['file']
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    encrypted_filename = "enc_" + filename
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    try:
        encrypt_file(input_path, encrypted_path, password)
        flash("File encrypted successfully!")
        return redirect(url_for('download', filename=encrypted_filename))
    except Exception as e:
        flash(f"Encryption failed: {str(e)}")
        return redirect(url_for('index'))

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files or request.files['file'].filename == '':
        flash("No encrypted file provided")
        return redirect(url_for('index'))

    password = request.form.get('password')
    if not password:
        flash("Password is required for decryption")
        return redirect(url_for('index'))

    encrypted_file = request.files['file']
    filename = secure_filename(encrypted_file.filename)
    input_path = os.path.join(ENCRYPTED_FOLDER, filename)
    encrypted_file.save(input_path)

    base_filename = filename.replace("enc_", "")
    decrypted_filename = "dec_" + base_filename
    output_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)

    try:
        decrypt_file(input_path, output_path, password)
        flash("File decrypted successfully!")
        return send_from_directory(DECRYPTED_FOLDER, decrypted_filename, as_attachment=True)
    except Exception as e:
        flash("Decryption failed. Check your password and file integrity.")
        return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
