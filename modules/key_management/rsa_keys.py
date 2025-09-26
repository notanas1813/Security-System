# modules/key_management/rsa_keys.py
import os, json, base64
from datetime import datetime, timedelta
from Crypto.PublicKey import RSA
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from modules.utils.config import KEY_DIR, RSA_KEY_TTL_DAYS
from modules.utils.logger import log_action

META_FILE = os.path.join(KEY_DIR, 'keys_metadata.json')

def _load_meta():
    if os.path.exists(META_FILE):
        return json.load(open(META_FILE, 'r', encoding='utf-8'))
    return {}

def _save_meta(meta):
    os.makedirs(KEY_DIR, exist_ok=True)
    with open(META_FILE, 'w', encoding='utf-8') as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

def create_rsa_keypair(email: str, passphrase: str):
    """Tạo RSA 2048, AES-encrypt private key, lưu metadata."""
    os.makedirs(KEY_DIR, exist_ok=True)
    key = RSA.generate(2048)
    priv_pem = key.export_key()
    pub_pem  = key.publickey().export_key()

    # derive AES key từ passphrase
    salt = get_random_bytes(16)
    aes_key = PBKDF2(passphrase, salt, dkLen=32, count=100_000)

    # AES-GCM encrypt private key
    cipher = AES.new(aes_key, AES.MODE_GCM)
    ct, tag = cipher.encrypt_and_digest(priv_pem)

    # Lưu files
    priv_path = os.path.join(KEY_DIR, f"{email}_private.pem.enc")
    pub_path  = os.path.join(KEY_DIR, f"{email}_public.pem")
    with open(priv_path, 'wb') as f:
        # lưu: salt|nonce|tag|ciphertext
        f.write(salt + cipher.nonce + tag + ct)
    with open(pub_path, 'wb') as f:
        f.write(pub_pem)

    # Lưu metadata
    meta = _load_meta()
    meta[email.lower()] = {
      'created_at': datetime.now().isoformat(),
      'expires_at': (datetime.now() + timedelta(days=RSA_KEY_TTL_DAYS)).isoformat(),
      'priv_file': os.path.basename(priv_path),
      'pub_file' : os.path.basename(pub_path)
    }
    _save_meta(meta)
    log_action(email, 'rsa_keypair', 'created')
    return pub_path, priv_path

def load_metadata(email: str):
    meta = _load_meta()
    return meta.get(email.lower())

def is_key_expired(email: str) -> bool:
    md = load_metadata(email)
    if not md: return True
    return datetime.now() > datetime.fromisoformat(md['expires_at'])

def renew_key_if_needed(email: str, passphrase: str):
    if is_key_expired(email):
        return create_rsa_keypair(email, passphrase)
    return (
      os.path.join(KEY_DIR, load_metadata(email)['pub_file']),
      os.path.join(KEY_DIR, load_metadata(email)['priv_file'])
    )

def remove_keypair(email: str) -> bool:
    """
    Xóa cả file private và public của email, và cập nhật metadata.
    Trả về True nếu có key để xóa, False nếu không tìm thấy.
    """
    meta = _load_meta()
    entry = meta.pop(email.lower(), None)
    if not entry:
        return False

    # Xóa file private và public
    for fname in (entry['priv_file'], entry['pub_file']):
        path = os.path.join(KEY_DIR, fname)
        if os.path.exists(path):
            os.remove(path)

    # Cập nhật metadata
    _save_meta(meta)
    log_action(email, 'rsa_keypair', 'removed')
    return True