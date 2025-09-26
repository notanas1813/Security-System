# modules/crypto_module/signature.py

import os
import json
import base64
from datetime import datetime

from Crypto.Hash      import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.PublicKey import RSA
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher     import AES

from modules.key_management.rsa_keys          import load_metadata, is_key_expired, _load_meta
from modules.key_management.public_key_search import find_public_key
from modules.utils.config                     import KEY_DIR
from modules.utils.logger                     import log_action

def sign_file(input_path: str, email: str, passphrase: str):
    # → 1) Bắt lỗi nếu chưa có key hoặc key hết hạn
    md = load_metadata(email)
    if not md:
        raise FileNotFoundError(
          "❌ Bạn chưa có RSA key. Vui lòng tạo khóa tại menu Quản lý khóa RSA trước khi ký."
        )
    if is_key_expired(email):
        raise ValueError(
          "❌ RSA key đã hết hạn. Vui lòng gia hạn tại menu Quản lý khóa RSA trước khi ký."
        )

    # → 2) Lấy path tới private PEM đã mã hóa
    priv_enc = os.path.join(KEY_DIR, md['priv_file'])
    with open(priv_enc, 'rb') as f:
        raw = f.read()
    salt, nonce, tag, ct = raw[:16], raw[16:32], raw[32:48], raw[48:]

    # → 3) Derive AES key và decrypt private PEM
    aes_key = PBKDF2(passphrase, salt, dkLen=32, count=100_000)
    cipher  = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    priv_pem = cipher.decrypt_and_verify(ct, tag)

    # → 4) Tính SHA-256 & ký
    with open(input_path, 'rb') as f:
        data = f.read()
    h   = SHA256.new(data)
    key = RSA.import_key(priv_pem)
    sig = pkcs1_15.new(key).sign(h)

    # → 5) Gói .sig (JSON) và ghi file
    base, _  = os.path.splitext(input_path)
    sig_path = base + '.sig'
    sig_pkg  = {
        'signature': base64.b64encode(sig).decode(),
        'meta': {
            'signer':    email,
            'timestamp': datetime.now().isoformat()
        }
    }
    with open(sig_path, 'w', encoding='utf-8') as f:
        json.dump(sig_pkg, f, ensure_ascii=False, indent=2)

    # → 6) Log & trả về
    log_action(email, 'file_sign', 'success', os.path.basename(sig_path))
    return sig_path

def verify_signature(input_path: str, sig_path: str):
    """
    1) Đọc .sig (JSON base64) hoặc raw bytes fallback
    2) Tính SHA-256 của file gốc
    3) Nếu meta.signer tồn tại, thử verify bằng public key đó
    4) Nếu không, thử verify với toàn bộ public key đã lưu
    5) Trả về (bool, [email_signer,...])
    """
    # -- 1) Load signature --
    try:
        with open(sig_path, 'r', encoding='utf-8') as f:
            pkt = json.load(f)
        signature = base64.b64decode(pkt['signature'])
        signer    = pkt.get('meta', {}).get('signer')
    except (UnicodeDecodeError, json.JSONDecodeError, KeyError):
        # fallback raw-format
        with open(sig_path, 'rb') as f:
            signature = f.read()
        signer = None

    # -- 2) Hash file gốc --
    with open(input_path, 'rb') as f:
        data = f.read()
    h = SHA256.new(data)

    # -- 3) Thử verify bằng signer nếu có --
    if signer:
        pub_path = find_public_key(signer)
        if pub_path:
            pub_pem = open(pub_path, 'rb').read()
            key     = RSA.import_key(pub_pem)
            try:
                pkcs1_15.new(key).verify(h, signature)
                log_action(signer, 'sig_verify', 'success', os.path.basename(input_path))
                return True, [signer]
            except (ValueError, TypeError):
                pass

    # -- 4) Fallback: thử tất cả public key --
    all_meta = _load_meta()
    for email, info in all_meta.items():
        pub_file = os.path.join(KEY_DIR, info['pub_file'])
        with open(pub_file, 'rb') as f:
            pub_pem = f.read()
        key = RSA.import_key(pub_pem)
        try:
            pkcs1_15.new(key).verify(h, signature)
            log_action(email, 'sig_verify', 'success', os.path.basename(input_path))
            return True, [email]
        except (ValueError, TypeError):
            continue

    # -- 5) Không ai verify được --
    log_action('', 'sig_verify', 'fail', os.path.basename(input_path))
    return False, []