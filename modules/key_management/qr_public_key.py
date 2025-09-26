# Updated modules/key_management/qr_public_key.py

# modules/key_management/qr_public_key.py

import os
import json
import base64
from datetime import datetime, timedelta

import qrcode
from PIL import Image
from pyzbar.pyzbar import decode

from modules.utils.config import DATA_DIR, KEY_DIR
from modules.utils.logger import log_action
from modules.key_management.rsa_keys import (
    load_metadata,
    _load_meta,
    _save_meta
)

META_FILE = os.path.join(KEY_DIR, 'keys_metadata.json')


def create_qr_code_for_public_key(user_email: str) -> tuple[bool, str]:
    """
    Tạo QR code chứa JSON {
      'email','created_at','public_key'
    } rồi lưu PNG vào DATA_DIR.
    Trả về (True, đường_dẫn_file) hoặc (False, lỗi).
    """
    meta = load_metadata(user_email)
    if not meta:
        return False, "User chưa có keypair."
    pub_filename = meta['pub_file']
    pub_path = os.path.join(KEY_DIR, pub_filename)
    if not os.path.exists(pub_path):
        return False, "File public key không tồn tại."

    # đọc public key và mã hóa Base64
    with open(pub_path, 'rb') as f:
        raw = f.read()
    key_b64 = base64.b64encode(raw).decode('utf-8')

    payload = json.dumps({
        'email':      user_email,
        'created_at': meta['created_at'],
        'public_key': key_b64
    }, ensure_ascii=False)

    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(payload)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")

    os.makedirs(DATA_DIR, exist_ok=True)
    qr_path = os.path.join(DATA_DIR, f"{user_email}_public_key_qr.png")
    img.save(qr_path)

    log_action(user_email, 'create_qr_public_key', qr_path)
    return True, qr_path



def read_qr_code_from_file(qr_file_path: str,
                           importer_email: str) -> tuple[bool, str | dict]:
    """
    Đọc QR từ file, parse JSON, và:
      - Nếu user đã tồn tại trong metadata:
          • Ghi đè public key từ QR.
          • Cập nhật created_at = thời điểm quét.
          • expires_at = created_at + 90 ngày.
          • Giữ nguyên priv_file.
      - Nếu user mới:
          • Tạo entry mới với priv_file=None.
          • Cập nhật created_at và expires_at tương tự.

    Cập nhật metadata trong META_FILE (keys_metadata.json).
    Trả về (True, metadata_entry) hoặc (False, lỗi).
    """
    # 1) đọc ảnh và decode QR
    try:
        img = Image.open(qr_file_path)
    except Exception as e:
        return False, f"Không mở được file ảnh: {e}"

    decoded = decode(img)
    if not decoded:
        return False, "Không đọc được QR code từ file."

    # 2) parse JSON
    try:
        info = json.loads(decoded[0].data.decode('utf-8'))
        email      = info['email']
        key_b64    = info['public_key']
    except Exception as e:
        return False, f"Dữ liệu QR không hợp lệ: {e}"

    # 3) chuyển Base64 → bytes
    try:
        pub_bytes = base64.b64decode(key_b64.encode('utf-8'))
    except Exception as e:
        return False, f"Base64 decode lỗi: {e}"

    # 4) ghi file public.pem (ghi đè)
    os.makedirs(KEY_DIR, exist_ok=True)
    pub_filename = f"{email}_public.pem"
    pub_path = os.path.join(KEY_DIR, pub_filename)
    try:
        with open(pub_path, 'wb') as f:
            f.write(pub_bytes)
    except Exception as e:
        return False, f"Lỗi ghi public key: {e}"

    # 5) cập nhật metadata
    meta = _load_meta()  # metadata hiện tại (dict email→entry)
    lower = email.lower()
    old_priv = None
    if lower in meta:
        old_priv = meta[lower].get('priv_file')

    now = datetime.now()
    created = now.isoformat()
    expires = (now + timedelta(days=90)).isoformat()

    entry = {
        'created_at': created,
        'expires_at': expires,
        'priv_file':  old_priv,
        'pub_file':   pub_filename
    }
    meta[lower] = entry
    _save_meta(meta)

    log_action(importer_email, 'import_qr_public_key', pub_path)
    return True, entry