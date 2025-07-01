import tkinter as tk
from tkinter import scrolledtext, simpledialog, filedialog
import socket
import threading
import time
import os
import json
from cryptography_utils import *


class ReceiverApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Bên nhận")
        self.root.geometry("500x400")

        self.log_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, state='disabled')
        self.log_area.pack(padx=10, pady=10, fill=tk.BOTH, expand=True)

        self.start_button = tk.Button(root, text="Ready!", command=self.start_listening)
        self.start_button.pack(pady=5)

        # Tải khóa private của người nhận
        try:
            self.receiver_private_key = load_rsa_key("receiver_private.pem")
            self.sender_public_key = load_rsa_key("sender_public.pem")
            self.log_message("Đã tải khóa RSA của người nhận và người gửi.")
        except FileNotFoundError:
            self.log_message("LỖI: Không tìm thấy file khóa. Vui lòng chạy generate_keys.py trước.")
            self.start_button.config(state='disabled')

    def log_message(self, message):
        self.log_area.config(state='normal')
        self.log_area.insert(tk.END, f"{time.strftime('%H:%M:%S')} - {message}\n")
        self.log_area.yview(tk.END)
        self.log_area.config(state='disabled')

    def start_listening(self):
        self.start_button.config(state='disabled')
        self.log_message("Server đang lắng nghe trên cổng 9999...")
        thread = threading.Thread(target=self.listen_thread, daemon=True)
        thread.start()

    def listen_thread(self):
        host = '0.0.0.0'
        port = 9999

        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind((host, port))
            s.listen()
            conn, addr = s.accept()
            with conn:
                self.log_message(f"Kết nối từ {addr}")

                try:
                    # 1. Handshake
                    hello = conn.recv(1024).decode()
                    if hello != "Hello!":
                        raise ValueError("Handshake thất bại.")
                    conn.sendall(b"Ready!")
                    self.log_message("Handshake thành công.")

                    # 2. Nhận SessionKey và Metadata
                    control_message = receive_message(conn)
                    encrypted_key_b64 = control_message['encrypted_key']
                    metadata = control_message['metadata']
                    signature_b64 = control_message['signature']

                    # Xác thực chữ ký của metadata
                    metadata_bytes = json.dumps(metadata, sort_keys=True).encode('utf-8')
                    if not verify_signature(metadata_bytes, signature_b64, self.sender_public_key):
                        raise ValueError("Chữ ký metadata không hợp lệ!")
                    self.log_message("Chữ ký metadata hợp lệ.")

                    # Giải mã session key
                    session_key = decrypt_rsa(encrypted_key_b64, self.receiver_private_key)
                    self.log_message("Đã giải mã Session Key thành công.")

                    # 3. Nhận các phần file
                    file_parts_data = {}
                    for _ in range(metadata['parts']):
                        part_message = receive_message(conn)
                        part_index = part_message['part_index']

                        # Kiểm tra hash
                        iv_b64 = part_message['iv']
                        cipher_b64 = part_message['cipher']
                        hash_received = part_message['hash']
                        hash_calculated = calculate_hash(iv_b64, cipher_b64)

                        if hash_received != hash_calculated:
                            raise ValueError(f"Hash của phần {part_index} không khớp!")

                        self.log_message(f"Hash của phần {part_index} hợp lệ.")
                        file_parts_data[part_index] = (iv_b64, cipher_b64)

                    self.log_message("Đã nhận đủ các phần file.")

                    # Gửi ACK
                    conn.sendall(b"ACK")

                    # Ghép và lưu file
                    save_path = filedialog.asksaveasfilename(
                        initialfile=metadata['filename'],
                        title="Lưu file",
                        filetypes=(("All files", "*.*"),)
                    )
                    if save_path:
                        full_content = b''
                        for i in sorted(file_parts_data.keys()):
                            iv_b64, cipher_b64 = file_parts_data[i]
                            iv = base64.b64decode(iv_b64)
                            decrypted_part = decrypt_des(cipher_b64, session_key, iv)
                            full_content += decrypted_part

                        with open(save_path, 'wb') as f:
                            f.write(full_content)
                        self.log_message(f"File đã được giải mã và lưu tại: {save_path}")
                    else:
                        self.log_message("Người dùng đã hủy lưu file.")

                except Exception as e:
                    self.log_message(f"LỖI: {e}")
                    try:
                        conn.sendall(b"NACK")
                    except:
                        pass  # Kết nối có thể đã đóng
                finally:
                    self.log_message("Đóng kết nối.")
                    self.start_button.config(state='normal')


if __name__ == "__main__":
    root = tk.Tk()
    app = ReceiverApp(root)
    root.mainloop()