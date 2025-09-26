import os
import json
import base64
from datetime import datetime

from Crypto.Cipher       import AES, PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey    import RSA

from modules.key_management.rsa_keys       import load_metadata, is_key_expired
from modules.crypto_module.format_handler  import unpack_encrypted
from modules.utils.config                  import DECRYPTED_DIR, KEY_DIR
from modules.utils.logger                  import log_action

def decrypt_file(enc_path: str,
                 user_email: str,
                 passphrase: str,
                 merged: bool = True,
                 key_file_path: str = None):

    os.makedirs(DECRYPTED_DIR, exist_ok=True)

    # → 1) Bắt lỗi nếu user chưa có key hoặc key hết hạn
    md = load_metadata(user_email)
    if not md:
        raise FileNotFoundError(
          "❌ Bạn chưa có RSA key. Vui lòng vào Quản lý khóa RSA để tạo khóa trước khi giải mã."
        )
    if is_key_expired(user_email):
        raise ValueError(
          "❌ RSA key đã hết hạn. Vui lòng vào Quản lý khóa RSA để gia hạn trước khi giải mã."
        )

    # → 2) Lấy đường dẫn file private key đã mã hóa
    priv_enc_path = os.path.join(KEY_DIR, md['priv_file'])
    raw    = open(priv_enc_path, 'rb').read()
    salt   = raw[0:16]
    nonce1 = raw[16:32]
    tag1   = raw[32:48]
    ct1    = raw[48:]

    # → 3) Derive AES key và decrypt private PEM
    aes_key = PBKDF2(passphrase, salt, dkLen=32, count=100_000)
    cipher1 = AES.new(aes_key, AES.MODE_GCM, nonce=nonce1)
    priv_pem = cipher1.decrypt_and_verify(ct1, tag1)

    priv_key   = RSA.import_key(priv_pem)
    rsa_cipher = PKCS1_OAEP.new(priv_key)

    # → 4) Unpack metadata / ciphertext / enc_skey
    if merged:
        pkg               = open(enc_path, 'rb').read()
        meta, enc_skey, all_ct = unpack_encrypted(pkg)
    else:
        all_ct   = open(enc_path, 'rb').read()
        key_info = json.load(open(key_file_path, 'r'))
        meta     = key_info['meta']
        enc_skey = base64.b64decode(key_info['enc_skey'])

    # → 5) RSA-decrypt session key
    session_key = rsa_cipher.decrypt(enc_skey)

    # → 6) AES-GCM decrypt dữ liệu
    nonce2  = base64.b64decode(meta['nonce'])
    cipher2 = AES.new(session_key, AES.MODE_GCM, nonce=nonce2)
    tag_len = 16
    tag     = all_ct[:tag_len]
    ct      = all_ct[tag_len:]
    plaintext = cipher2.decrypt_and_verify(ct, tag)

    # → 7) Lưu file gốc
    original_name = meta.get('original_filename', os.path.basename(enc_path))
    out_path      = os.path.join(DECRYPTED_DIR, original_name)
    with open(out_path, 'wb') as f:
        f.write(plaintext)

    # → 8) Ghi log & return
    log_action(user_email, 'file_decrypt', 'success', meta.get('sender',''))
    return out_path, meta