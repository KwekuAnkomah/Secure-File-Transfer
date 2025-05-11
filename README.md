Secure File Transfer System
A Flask-based encryption tool that securely transfers files using AES encryption to protect sensitive data during transmission.

📌 Overview
This project enables secure file transfers by encrypting files before sending and decrypting them upon receipt using AES (Advanced Encryption Standard). It ensures that even if a file is intercepted, it remains unreadable without the correct password.

🎯 Features
File Encryption & Decryption using AES (CBC mode)

Password-Based Security with PBKDF2 key derivation

User-Friendly Web Interface for easy interaction

Automatic Encrypted File Download after encryption

Secure File Storage in uploads/encrypted/decrypted directories

🛠 Technology Stack
Component	Purpose
Python 3.x	Backend programming
Flask	Web framework for file handling
PyCryptodome	AES encryption library
Bootstrap	Responsive UI styling
PyCharm	Development IDE
📂 Project Structure
Secure-File-Transfer/
│── uploads/           # Stores raw uploaded files
│── encrypted/         # Stores encrypted files
│── decrypted/         # Stores decrypted files
│── templates/         # Contains the HTML interface (index.html)
│── app.py             # Main Flask application
│── requirements.txt   # Dependencies list (Flask, PyCryptodome)
│── README.md          # Project documentation
🔑 Installation
1️⃣ Clone Repository
bash
git clone https://github.com/YOUR-USERNAME/secure-file-transfer.git
cd secure-file-transfer
2️⃣ Install Dependencies
bash
pip install -r requirements.txt
3️⃣ Run Flask Application
bash
python app.py
Access the web interface at http://127.0.0.1:5000

🛡️ How Encryption Works
User uploads a file via the web interface.

System encrypts the file using AES encryption (CBC mode).

User downloads the encrypted file for transfer.

Recipient uploads the encrypted file and provides the correct password.

System decrypts the file to restore its original form.

🧩 Code Breakdown
🔹 Flask App Setup
python
app = Flask(__name__)
app.secret_key = "your_secret_key"
Purpose: Initializes Flask and sets up a secret key for session management.

🔹 File Handling Directories
python
UPLOAD_FOLDER = "uploads"
ENCRYPTED_FOLDER = "encrypted"
DECRYPTED_FOLDER = "decrypted"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)
Purpose: Ensures directories exist for storing different file states.

🔹 Padding & Unpadding (AES Requirement)
python
def pad(data):
    pad_len = AES.block_size - (len(data) % AES.block_size)
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]
Purpose: Ensures that files match AES's block size requirements.

🔹 Encryption Function
python
def encrypt_file(input_filepath, output_filepath, password):
    salt = get_random_bytes(16)
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC)

    with open(input_filepath, 'rb') as f:
        plaintext = f.read()

    padded_plaintext = pad(plaintext)
    ciphertext = cipher.encrypt(padded_plaintext)

    with open(output_filepath, 'wb') as f:
        f.write(salt + cipher.iv + ciphertext)
Purpose: Encrypts files using AES (CBC mode) and securely stores the salt & IV.

🔹 Decryption Function
python
def decrypt_file(input_filepath, output_filepath, password):
    with open(input_filepath, 'rb') as f:
        file_data = f.read()

    salt, iv, ciphertext = file_data[:16], file_data[16:32], file_data[32:]
    key = PBKDF2(password, salt, dkLen=32, count=100000)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext))

    with open(output_filepath, 'wb') as f:
        f.write(plaintext)
Purpose: Extracts stored encryption details and restores the original file using the correct password.

🔹 File Upload & Encryption Route
python
@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    password = request.form.get('password')
    filename = secure_filename(file.filename)
    input_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(input_path)

    encrypted_filename = "enc_" + filename
    encrypted_path = os.path.join(ENCRYPTED_FOLDER, encrypted_filename)

    encrypt_file(input_path, encrypted_path, password)
    return redirect(url_for('download', filename=encrypted_filename))
Purpose: Handles file upload, encrypts it, and automatically provides download access.

🔹 Encrypted File Download Route
python
@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(ENCRYPTED_FOLDER, filename, as_attachment=True)
Purpose: Provides immediate download access for encrypted files.

🔹 Decryption Route
python
@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files['file']
    password = request.form.get('password')
    filename = secure_filename(file.filename)
    input_path = os.path.join(ENCRYPTED_FOLDER, filename)
    file.save(input_path)

    decrypted_filename = "dec_" + filename.replace("enc_", "")
    output_path = os.path.join(DECRYPTED_FOLDER, decrypted_filename)

    decrypt_file(input_path, output_path, password)
    return send_from_directory(DECRYPTED_FOLDER, decrypted_filename, as_attachment=True)
Purpose: Ensures that encrypted files are restored to their original format when the correct password is provided.

🔹 Running the Flask App
python
if __name__ == '__main__':
    app.run(debug=True)
Purpose: Starts the Flask development server for local testing.

🔍 Screenshots & Testing Process
Uploading a file for encryption.

Entering a password to encrypt the file.

Downloading the encrypted file from the browser.

Decrypting the file using the correct password.

🎯 Future Improvements
Implement two-factor authentication for extra security.

Allow users to store and retrieve encryption keys securely.

Provide file size optimization for large uploads.

Enhance the UI with better styling and feedback mechanisms.
