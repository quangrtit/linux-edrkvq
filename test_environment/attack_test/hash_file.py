import hashlib

def sha256_of_file(filename):
    sha256 = hashlib.sha256()
    try:
        with open(filename, "rb") as f:
            # Đọc file theo từng khối 4KB để tránh tốn RAM với file lớn
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except FileNotFoundError:
        return "❌ File không tồn tại!"
    except Exception as e:
        return f"⚠️ Lỗi: {e}"

if __name__ == "__main__":
    filepath = input("Nhập đường dẫn file: ").strip()
    print("SHA256:", sha256_of_file(filepath))
