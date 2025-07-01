from Crypto.PublicKey import RSA


def generate_and_save_keys(name, key_size=1024):
    """Tạo và lưu cặp khóa RSA."""
    try:
        key = RSA.generate(key_size)

        # Xuất và lưu private key
        private_key = key.export_key()
        with open(f"{name}_private.pem", "wb") as f_priv:
            f_priv.write(private_key)

        # Xuất và lưu public key
        public_key = key.publickey().export_key()
        with open(f"{name}_public.pem", "wb") as f_pub:
            f_pub.write(public_key)

        print(f"Đã tạo thành công khóa cho '{name}' tại {name}_private.pem và {name}_public.pem")
    except Exception as e:
        print(f"Lỗi khi tạo khóa cho {name}: {e}")


if __name__ == "__main__":
    print("Bắt đầu tạo khóa RSA (1024-bit)...")
    generate_and_save_keys("sender")
    generate_and_save_keys("receiver")
    print("Hoàn tất.")