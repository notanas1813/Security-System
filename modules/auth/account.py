# modules/auth/account.py

import os, json, hashlib, secrets, re
from datetime import datetime
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher       import AES

from modules.utils.config        import USERS_FILE, LOG_FILE
from modules.utils.logger        import log_action
from modules.key_management.rsa_keys import (
    create_rsa_keypair,
    remove_keypair,
    load_metadata
)

# Regex đơn giản để validate email
EMAIL_REGEX = r'^[\w\.-]+@[\w\.-]+\.\w+$'
def is_valid_email(email: str) -> bool:
    return re.match(EMAIL_REGEX, email) is not None

def load_users() -> list[dict]:
    if not os.path.exists(USERS_FILE):
        return []
    with open(USERS_FILE, 'r', encoding='utf-8') as f:
        try: return json.load(f)
        except: return []

def save_users(users: list[dict]) -> None:
    os.makedirs(os.path.dirname(USERS_FILE), exist_ok=True)
    with open(USERS_FILE, 'w', encoding='utf-8') as f:
        json.dump(users, f, indent=2, ensure_ascii=False)

def is_strong_passphrase(pw: str) -> bool:
    if len(pw) < 8: return False
    if not any(c.isupper() for c in pw): return False
    if not any(c.isdigit() for c in pw): return False
    if not any(c in '!@#$%^&*()_+-=[]{},.<>/?;:\'"|`~' for c in pw):
        return False
    return True

def register_user(email, name, dob, phone, address, passphrase):
    # 1) kiểm định dạng email
    if not is_valid_email(email):
        log_action(email, 'register', 'fail: invalid_email')
        return False, 'Email không đúng định dạng.'
    users = load_users()

    # 2) kiểm trùng email
    if any(u['email'].lower() == email.lower() for u in users):
        log_action(email, 'register', 'fail: exists')
        return False, 'Email đã có.'

    # 3) kiểm passphrase
    if not is_strong_passphrase(passphrase):
        log_action(email, 'register', 'fail: weak_pw')
        return False, 'Passphrase yếu. Tối thiểu 8 ký tự, có chữ hoa, số, ký hiệu.'

    # 4) salt + hash SHA-256
    salt = secrets.token_hex(16)
    pass_hash = hashlib.sha256((passphrase + salt).encode()).hexdigest()

    # 5) tạo record và lưu
    new_user = {
      'email':      email,
      'name':       name,
      'dob':        dob,
      'phone':      phone,
      'address':    address,
      'salt':       salt,
      'pass_hash':  pass_hash,
      'created_at': datetime.now().isoformat(),
      'role':       'user',
      'locked':     False
    }
    users.append(new_user)
    save_users(users)

    # 6) tạo RSA keypair cho user, ghi log
    create_rsa_keypair(email, passphrase)
    log_action(email, 'register', 'success')
    return True, 'Đăng ký thành công.'

def verify_password(email: str, passphrase: str) -> tuple[bool, dict|None]:
    """
    Trả về (True, user_dict) nếu đúng passphrase, ngược lại (False, None).
    """
    for u in load_users():
        if u['email'].lower() == email.lower():
            h = hashlib.sha256((passphrase + u['salt']).encode()).hexdigest()
            if h == u['pass_hash']:
                log_action(email, 'verify_password', 'success')
                return True, u
    log_action(email, 'verify_password', 'fail')
    return False, None

def update_user_info(email, old_pw, new_info: dict):
    ok, _ = verify_password(email, old_pw)
    if not ok:
        log_action(email, 'update_info', 'fail: bad_pass')
        return False, 'Passphrase không đúng.'
    users = load_users()
    for u in users:
        if u['email'].lower() == email.lower():
            for k in ('name','dob','phone','address'):
                if k in new_info:
                    u[k] = new_info[k]
            save_users(users)
            log_action(email, 'update_info', 'success')
            return True, 'Cập nhật thông tin thành công.'
    return False, 'Không tìm thấy tài khoản.'

def change_passphrase(email, old_pw, new_pw):
    # 1) Xác thực pass cũ và độ mạnh pass mới
    ok, _ = verify_password(email, old_pw)
    if not ok:
        log_action(email, 'change_passphrase', 'fail: bad_old')
        return False, 'Passphrase hiện tại không đúng.'
    if not is_strong_passphrase(new_pw):
        return False, 'Passphrase mới yếu.'

    # 2) Cập nhật salt+hash trong users DB
    new_salt_bytes = secrets.token_bytes(16)       # 16 raw bytes
    new_salt_hex   = new_salt_bytes.hex()          # lưu dạng hex vào JSON
    new_hash       = hashlib.sha256((new_pw + new_salt_hex).encode()).hexdigest()

    users = load_users()
    for u in users:
        if u['email'].lower() == email.lower():
            u['salt']      = new_salt_hex
            u['pass_hash'] = new_hash
            break
    save_users(users)

    # 3) Đọc file đã mã hóa
    md       = load_metadata(email)
    priv_enc = os.path.join(os.path.dirname(USERS_FILE), 'keys', md['priv_file'])
    blob     = open(priv_enc, 'rb').read()

    # Khai báo hằng
    SALT_LEN   = 16
    NONCE_LEN  = 16  # default GCM nonce length
    TAG_LEN    = 16

    # Slice theo đúng thứ tự salt|nonce|tag|ciphertext
    salt_old  = blob[0:SALT_LEN]
    nonce_old = blob[SALT_LEN:SALT_LEN+NONCE_LEN]
    tag_old   = blob[SALT_LEN+NONCE_LEN:SALT_LEN+NONCE_LEN+TAG_LEN]
    ct_old    = blob[SALT_LEN+NONCE_LEN+TAG_LEN:]

    # 4) Giải mã private key
    key_old = PBKDF2(old_pw, salt_old, dkLen=32, count=100_000)
    cipher1 = AES.new(key_old, AES.MODE_GCM, nonce=nonce_old)
    try:
        priv_pem = cipher1.decrypt_and_verify(ct_old, tag_old)
    except ValueError:
        return False, 'Không thể giải mã private key (pass cũ sai hoặc file hỏng).'

    # 5) Re-encrypt với passphrase mới
    new_salt_bytes = secrets.token_bytes(SALT_LEN)
    key_new        = PBKDF2(new_pw, new_salt_bytes, dkLen=32, count=100_000)
    cipher2        = AES.new(key_new, AES.MODE_GCM)
    ct_new, tag_new= cipher2.encrypt_and_digest(priv_pem)

    # 6) Ghi lại file theo đúng thứ tự salt|nonce|tag|ciphertext
    with open(priv_enc, 'wb') as f:
        f.write(new_salt_bytes)       # 16 bytes
        f.write(cipher2.nonce)        # 16 bytes
        f.write(tag_new)              # 16 bytes
        f.write(ct_new)               # phần ciphertext

    log_action(email, 'change_passphrase', 'success')
    return True, 'Đổi passphrase thành công.'

def get_user_info(email):
    for u in load_users():
        if u['email'].lower() == email.lower():
            return {k: u[k] for k in (
                'email','name','dob','phone','address','created_at','role')}
    return None

def delete_account(email, pw):
    ok, _ = verify_password(email, pw)
    if not ok:
        log_action(email, 'delete_account', 'fail: bad_pass')
        return False, 'Passphrase không đúng.'
    users = [u for u in load_users() if u['email'].lower() != email.lower()]
    save_users(users)
    remove_keypair(email)
    log_action(email, 'delete_account', 'success')
    return True, 'Tài khoản đã xóa.'