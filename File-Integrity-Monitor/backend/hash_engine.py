import hashlib

def calculate_sha256(path, chunk_size=1024 * 1024):
    """Return the SHA-256 hash of a file."""
    sha256 = hashlib.sha256()
    with open(path, 'rb') as file:
        while True:
            chunk = file.read(chunk_size)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()
