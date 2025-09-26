# modules/crypto_module/file_encrypt.py

import os, json, base64
from datetime import datetime
from Crypto.Cipher    import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random    import get_random_bytes

from modules.key_management.public_key_search import find_public_key
from modules.crypto_module.format_handler      import package_encrypted
from modules.utils.config                      import ENCRYPTED_DIR
from modules.utils.logger                      import log_action

def encrypt_file(input_path: str,
                 sender_email: str,
                 recipient_email: str,
                 merged=True):

    os.makedirs(ENCRYPTED_DIR, exist_ok=True)

    # --- 1) Load public key recipient ---
    pub_path = find_public_key(recipient_email)
    if not pub_path:
        raise FileNotFoundError("Public key không tìm thấy")
    recipient_key = RSA.import_key(open(pub_path,'rb').read())
    rsa_cipher    = PKCS1_OAEP.new(recipient_key)

    # --- 2) Sinh session key + AES-GCM streaming ---
    session_key = get_random_bytes(32)
    aes = AES.new(session_key, AES.MODE_GCM)
    nonce = aes.nonce

    # Đọc và encrypt file theo từng đoạn (1 MB mỗi lần)
    ciphertext = b''
    with open(input_path, 'rb') as f:
        while True:
            chunk = f.read(1024*1024)
            if not chunk:
                break
            ciphertext += aes.encrypt(chunk)
    tag = aes.digest()

    # --- 3) Mã hóa session key bằng RSA ---
    enc_skey = rsa_cipher.encrypt(session_key)

    # --- 4) Tạo metadata ---
    meta = {
        'sender':            sender_email,
        'recipient':         recipient_email,
        'original_filename': os.path.basename(input_path),
        'timestamp':         datetime.now().isoformat(),
        'nonce':             base64.b64encode(nonce).decode()
    }

    # --- 5) Xuất file ---
    name_only, _ = os.path.splitext(os.path.basename(input_path))
    if merged:
        # Gộp tag + ciphertext + phiên key vào 1 file
        pkg = package_encrypted(meta, tag + ciphertext, enc_skey)
        out_file = os.path.join(ENCRYPTED_DIR, f"{name_only}.enc")
        with open(out_file, 'wb') as f:
            f.write(pkg)
        log_action(sender_email, 'file_encrypt', 'success', recipient_email)
        return out_file

    else:
        # Tách riêng
        # .enc chứa tag + ciphertext
        ct_file = os.path.join(ENCRYPTED_DIR, f"{name_only}.enc")
        with open(ct_file,'wb') as f:
            f.write(tag + ciphertext)

        # .key chứa metadata + enc_skey
        key_file = os.path.join(ENCRYPTED_DIR, f"{name_only}_key.key")
        key_info = {
            'meta':     meta,
            'enc_skey': base64.b64encode(enc_skey).decode()
        }
        with open(key_file,'w') as f:
            json.dump(key_info, f, indent=2)

        log_action(sender_email, 'file_encrypt', 'success', recipient_email)
        return ct_file, key_file