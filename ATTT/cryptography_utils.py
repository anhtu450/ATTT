import os
import json
import base64
from Crypto.PublicKey import RSA
from Crypto.Cipher import DES, PKCS1_v1_5
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA512
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

BLOCK_SIZE_DES = 8 # Kích thước khối của DES là 8 bytes

# --- Quản lý khóa RSA ---
def load_rsa_key(key_path):
    """Tải khóa RSA từ file."""
    with open(key_path, 'rb') as f:
        return RSA.import_key(f.read())

# --- Mã hóa/Giải mã RSA (cho Session Key) ---
def encrypt_rsa(data, public_key):
    """Mã hóa dữ liệu bằng Public Key RSA (PKCS#1 v1.5)."""
    cipher_rsa = PKCS1_v1_5.new(public_key)
    encrypted_data = cipher_rsa.encrypt(data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_rsa(encrypted_data_b64, private_key):
    """Giải mã dữ liệu bằng Private Key RSA (PKCS#1 v1.5)."""
    encrypted_data = base64.b64decode(encrypted_data_b64)
    cipher_rsa = PKCS1_v1_5.new(private_key)
    # Cần một sentinel để xử lý lỗi giải mã
    sentinel = get_random_bytes(16)
    decrypted_data = cipher_rsa.decrypt(encrypted_data, sentinel)
    return decrypted_data

# --- Ký số/Xác thực RSA (cho Metadata) ---
def sign_data(data, private_key):
    """Ký lên dữ liệu bằng Private Key RSA và SHA-512."""
    h = SHA512.new(data)
    signer = pkcs1_15.new(private_key)
    signature = signer.sign(h)
    return base64.b64encode(signature).decode('utf-8')

def verify_signature(data, signature_b64, public_key):
    """Xác thực chữ ký bằng Public Key RSA và SHA-512."""
    h = SHA512.new(data)
    signature = base64.b64decode(signature_b64)
    verifier = pkcs1_15.new(public_key)
    try:
        verifier.verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# --- Mã hóa/Giải mã DES (cho File) ---
def encrypt_des(data, key, iv):
    """Mã hóa dữ liệu bằng DES (chế độ CBC)."""
    cipher_des = DES.new(key, DES.MODE_CBC, iv)
    padded_data = pad(data, BLOCK_SIZE_DES)
    encrypted_data = cipher_des.encrypt(padded_data)
    return base64.b64encode(encrypted_data).decode('utf-8')

def decrypt_des(encrypted_data_b64, key, iv):
    """Giải mã dữ liệu bằng DES (chế độ CBC)."""
    encrypted_data = base64.b64decode(encrypted_data_b64)
    cipher_des = DES.new(key, DES.MODE_CBC, iv)
    decrypted_data = cipher_des.decrypt(encrypted_data)
    unpadded_data = unpad(decrypted_data, BLOCK_SIZE_DES)
    return unpadded_data

# --- Hashing ---
def calculate_hash(iv_b64, cipher_b64):
    """Tính hash SHA-512 cho IV và Ciphertext."""
    iv = base64.b64decode(iv_b64)
    cipher = base64.b64decode(cipher_b64)
    h = SHA512.new(iv + cipher)
    return h.hexdigest()

# --- Tiện ích mạng ---
def send_message(sock, data):
    """Gửi một đối tượng JSON qua socket với tiền tố độ dài."""
    message = json.dumps(data).encode('utf-8')
    msg_len = len(message)
    sock.sendall(msg_len.to_bytes(4, 'big'))
    sock.sendall(message)

def receive_message(sock):
    """Nhận một đối tượng JSON từ socket."""
    raw_msg_len = sock.recv(4)
    if not raw_msg_len:
        return None
    msg_len = int.from_bytes(raw_msg_len, 'big')
    message = sock.recv(msg_len)
    return json.loads(message.decode('utf-8'))