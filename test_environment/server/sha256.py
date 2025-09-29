import hashlib
import argparse
from pathlib import Path

def sha256_file(path, chunk_size=65536):
    """
    Trả về SHA-256 hex digest của file tại `path`.
    - path: str hoặc pathlib.Path
    - chunk_size: số byte đọc mỗi lần (mặc định 64 KiB)
    """
    h = hashlib.sha256()
    path = Path(path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {path!s}")

    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(chunk_size), b""):
            h.update(chunk)
    return h.hexdigest()

# Ví dụ CLI
def main():
    p = argparse.ArgumentParser(description="Compute SHA-256 of a file")
    p.add_argument("file", help="path to file")
    args = p.parse_args()
    try:
        digest = sha256_file(args.file)
        print(digest)
    except Exception as e:
        print("Error:", e)

if __name__ == "__main__":
    main()
