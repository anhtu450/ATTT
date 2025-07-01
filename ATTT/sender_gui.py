import tkinter as tk
from tkinter import filedialog, scrolledtext
import socket
import threading
import time
import os
import json
from cryptography_utils import *


class SenderApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bên gửi")
        self.root.geometry("500x450")

        # Khai báo biến
        self.file_path = tk.StringVar()

        # Frame cho việc chọn file
        file_frame = tk.Frame(root)
        file_frame.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(file_frame, text="File:").pack(side=tk.LEFT)
        tk.Entry(file_frame, textvariable=self.file_path, state='readonly').pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Button(file_frame, text="Chọn File", command=self.select_file).pack(side=tk.LEFT, padx=5)

        # Frame cho địa chỉ IP
        ip_frame = tk.Frame(root)
        ip_frame.pack(padx=10, pady=5, fill=tk.X)
        tk.Label(ip_frame, text="IP Người nhận:").pack(side=tk.LEFT)
        self.ip_entry = tk.Entry(ip_frame)
        self.ip_entry.insert(0, "127.0.0.1")  # Default IP
        self.ip_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Log area
        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        # Nút Gửi
        self.send_button = tk.Button(root, text="Gửi File", command=self.send_file)
        self.send_button.pack(pady=5)

        # Tải khóa
        try:
            self.sender_private_key = load_rsa_key("sender_private.pem")
            self.receiver_public_key = load_rsa_key("receiver_public.pem")
            self.log_message("Đã tải khóa RSA của người gửi và người nhận.")
        except FileNotFoundError:
            self.log_message("LỖI: Không tìm thấy file khóa. Vui lòng chạy generate_keys.py trước.")
            self.send_button.config(state='disabled')

    def log_message(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_area.yview(tk.END)
        self.log_area.config(state='disabled')

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.set(path)
            self.log_message(f"Đã chọn file: {os.path.basename(path)}")

    def send_file(self):
        if not self.file_path.get():
            self.log_message("Lỗi: Vui lòng chọn file trước khi gửi.")
            return

        self.send_button.config(state='disabled')
        thread = threading.Thread(target=self.send_thread, daemon=True)
        thread.start()

    def send_thread(self):
        host = self.ip_entry.get()
        port = 9999
        filepath = self.file_path.get()

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                self.log_message(f"Đang kết nối tới {host}:{port}...")
                s.connect((host, port))

                # 1. Handshake
                s.sendall(b"Hello!")
                ready = s.recv(1024).decode()
                if ready != "Ready!":
                    raise ConnectionAbortedError("Handshake thất bại.")
                self.log_message("Handshake thành công.")

                # 2. Chuẩn bị dữ liệu và gửi control message
                session_key = get_random_bytes(8)  # DES key is 8 bytes
                encrypted_key_b64 = encrypt_rsa(session_key, self.receiver_public_key)

                metadata = {
                    'filename': os.path.basename(filepath),
                    'timestamp': time.time(),
                    'parts': 3
                }
                metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
                signature_b64 = sign_data(metadata_bytes, self.sender_private_key)

                control_message = {
                    'encrypted_key': encrypted_key_b64,
                    'metadata': metadata,
                    'signature': signature_b64
                }
                send_message(s, control_message)
                self.log_message("Đã gửi Session Key (đã mã hóa) và Metadata (đã ký).")

                # 3. Đọc, chia file và gửi từng phần
                with open(filepath, 'rb') as f:
                    file_content = f.read()

                file_size = len(file_content)
                part_size = (file_size + 2) // 3  # Chia làm 3 phần gần bằng nhau

                for i in range(3):
                    start = i * part_size
                    end = start + part_size
                    part_data = file_content[start:end]

                    if not part_data: continue

                    iv = get_random_bytes(8)  # DES IV is 8 bytes
                    iv_b64 = base64.b64encode(iv).decode('utf-8')
                    cipher_b64 = encrypt_des(part_data, session_key, iv)
                    hash_val = calculate_hash(iv_b64, cipher_b64)

                    part_message = {
                        'part_index': i + 1,
                        'iv': iv_b64,
                        'cipher': cipher_b64,
                        'hash': hash_val
                    }
                    send_message(s, part_message)
                    self.log_message(f"Đã gửi phần {i + 1}/3.")
                    time.sleep(0.1)  # Thêm độ trễ nhỏ

                # 4. Nhận phản hồi
                response = s.recv(1024).decode()
                if response == "ACK":
                    self.log_message("Gửi file thành công! Người nhận đã xác nhận (ACK).")
                else:
                    self.log_message("Gửi file thất bại! Người nhận phản hồi (NACK).")

        except Exception as e:
            self.log_message(f"LỖI: {e}")
        finally:
            self.send_button.config(state='normal')


if __name__ == "__main__":
    root = tk.Tk()
    app = SenderApp(root)
    root.mainloop()