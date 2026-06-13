# RSA-Manager
🔐 Modern RSA key generator &amp; encryptor desktop app (2048/3072/4096-bit) with Windows 11/macOS styling. Encrypt text, auto/manual decrypt, copy to clipboard, light/dark mode.

## ✨ Features

- 🎨 **Modern UI** – Windows 11 / macOS native styling (Light/Dark mode toggle)
- 🔑 **RSA Key Generation** – 2048, 3072, or 4096-bit keys with OAEP padding (SHA-256)
- 📝 **Encrypt any text** – Securely encrypt messages using public keys
- 🔓 **Two decryption modes**:
  - **Auto Decrypt** – Instant decryption with the current private key
  - **Manual Decrypt** – Paste encrypted data + private key (secure for sharing)
- 💾 **Save/Load keys** – Export keys as `.pem` files, auto-save to `~/Documents/RSA_Keys/`
- 📋 **One-click copy** – Copy keys and encrypted data to clipboard
- ⚡ **Fast & lightweight** – Optimized for performance even with 4096-bit keys

## Screnshots
- <img width="959" height="604" alt="Screenshot 2026-06-13 122800" src="https://github.com/user-attachments/assets/3068e710-dde4-4ff8-aabf-6318bc9cc224" />


- ## 📦 Installation

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Step 1: Clone the repository
git clone https://github.com/chusmanarshad/RSA-Manager.git

cd RSA-Manager

### Step 2: Install dependencie
pip install -r requirements.txt

### Step 3: Run the application
python rsa_manager.py

### Create a standalone executable
## For Windows
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico rsa_manager.py
## For macOS
pyinstaller --onefile --windowed --add-binary="/System/Library/Frameworks/Tk.framework/Tk:." rsa_manager.py


 # 🚀 Usage Guide
1. Generate Keys
  Click 2048-bit, 3072-bit, or 4096-bit button

  Wait for key generation (3–5 seconds for 4096-bit)

  Public & private keys appear in text boxes

2. Encrypt a Message
  Type your message in the "Enter data to encrypt" field

  Click the Encrypt button

  Encrypted text appears in Base64 format

3. Decrypt
  Choose Auto Decrypt (uses current private key) OR

  Choose Manual Decrypt → paste encrypted data + private key

  Click Decrypt to see the original message

4. Manage Keys
  Click Export Keys to save as .pem files

  Click Import Public Key to encrypt with external keys

  Keys auto-save to Documents/RSA_Keys/
