# modules/auth/recovery_system.py

import os, json, secrets, hashlib, string
from getpass import getpass

from modules.auth.account import load_users, save_users
from modules.utils.config import RECOVERY_CODES_FILE
from modules.utils.config import RECOVERY_KEYS_DIR
from modules.utils.logger import log_action

def _load_recovery_codes() -> dict[str, str]:
    """Return mapping email→recovery_hash."""
    if not os.path.exists(RECOVERY_CODES_FILE):
        return {}
    with open(RECOVERY_CODES_FILE, 'r', encoding='utf-8') as f:
        try:
            return json.load(f)
        except:
            return {}

def _save_recovery_codes(codes: dict[str, str]) -> None:
    """Ghi mapping email→recovery_hash."""
    os.makedirs(os.path.dirname(RECOVERY_CODES_FILE), exist_ok=True)
    with open(RECOVERY_CODES_FILE, 'w', encoding='utf-8') as f:
        json.dump(codes, f, indent=2, ensure_ascii=False)

def generate_recovery_code(email: str) -> tuple[bool, str]:
    """
    Sinh một lần duy nhất Recovery Code cho mỗi email.
    Trả về (True, "Recovery code: ABC12345") hoặc (False, lý do).
    """
    rc = _load_recovery_codes()
    key = email.lower()
    if key in rc:
        return False, "Bạn đã có recovery code rồi, không thể tạo mới."

    alphabet = string.ascii_uppercase + string.digits
    code     = ''.join(secrets.choice(alphabet) for _ in range(8))
    rc[key]  = hashlib.sha256(code.encode()).hexdigest()
    _save_recovery_codes(rc)

    log_action(email, 'generate_recovery_code', 'success')
    return True, f"Recovery code: {code}\nLƯU Ý: chỉ hiển thị 1 lần!"

def verify_recovery_code(email: str, code: str) -> tuple[bool, str]:
    """
    Kiểm tra email có hash trong JSON và hash(code) đúng không.
    Code có thể dùng lại nhiều lần.
    """
    rc = _load_recovery_codes()
    h = rc.get(email.lower())
    if not h:
        return False, "Chưa có recovery code cho email này."
    if hashlib.sha256(code.encode()).hexdigest() != h:
        return False, "Recovery code không đúng."
    return True, "Recovery code hợp lệ."

def reset_password_with_recovery(email: str,
                                 code: str,
                                 new_pw: str) -> tuple[bool, str]:
    """
    1) Verify code
    2) Cập nhật salt & pass_hash trong users.json
    (Không đánh dấu 'used'—code dùng mãi mãi)
    """
    ok, msg = verify_recovery_code(email, code)
    if not ok:
        return False, msg

    users = load_users()
    for u in users:
        if u['email'].lower() == email.lower():
            salt = secrets.token_hex(16)
            u['salt']      = salt
            u['pass_hash'] = hashlib.sha256((new_pw + salt).encode()).hexdigest()
            break
    save_users(users)

    log_action(email, 'reset_password_with_recovery', 'success')
    return True, "Đã đặt lại passphrase thành công."

def delete_recovery_code(email: str) -> None:
    """
    Xóa entry recovery code của email (nếu có) trong recovery_codes.json.
    """
    rc = _load_recovery_codes()
    key = email.lower()
    if key in rc:
        rc.pop(key)
        _save_recovery_codes(rc)
        log_action(email, 'delete_recovery_code', 'success')

def delete_recovery_backup(email: str) -> None:
    """
    Xóa file backup private-key mã hóa bằng recovery code.
    """
    path = os.path.join(RECOVERY_KEYS_DIR, f"{email}_recovery.key")
    if os.path.exists(path):
        os.remove(path)
        log_action(email, 'delete_recovery_backup', 'success')