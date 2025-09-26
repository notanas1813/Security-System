# modules/auth/admin_management.py

import os
import hashlib
from datetime import datetime, timedelta
from modules.auth.account import load_users, save_users
from modules.utils.logger import log_action

# Đường dẫn tới file log (phù hợp với modules/utils/logger.py)
LOG_FILE = os.path.abspath(
    os.path.join(os.path.dirname(__file__), '../../data/security.log')
)


def is_admin_or_owner(email: str) -> bool:
    """True nếu email có role = 'admin' hoặc 'owner'."""
    for u in load_users():
        if u['email'].lower() == email.lower():
            return u.get('role') in ('admin', 'owner')
    return False


def is_owner(email: str) -> bool:
    """True chỉ khi email có role = 'owner'."""
    for u in load_users():
        if u['email'].lower() == email.lower():
            return u.get('role') == 'owner'
    return False


def verify_password(email: str, pw: str) -> tuple[bool, str]:
    """
    Xác thực passphrase bằng cách load_users và so SHA256(pw+salt) với pass_hash.
    Trả về (True, None) nếu đúng, (False, lý_do) nếu sai.
    """
    for u in load_users():
        if u['email'].lower() == email.lower():
            salt = u['salt']
            h = hashlib.sha256((pw + salt).encode()).hexdigest()
            return (h == u['pass_hash'],
                    None if h == u['pass_hash'] else "Passphrase không đúng.")
    return False, "Không tìm thấy user."


def list_all_users(admin_email: str) -> tuple[bool, list[dict] | str]:
    """Chỉ admin/owner: trả về danh sách dict {email,name,created_at,role,locked}."""
    if not is_admin_or_owner(admin_email):
        log_action(admin_email, 'list_users', 'fail: not_admin')
        return False, "Bạn không có quyền admin."
    users = load_users()
    result = []
    for u in users:
        result.append({
            'email':      u['email'],
            'name':       u.get('name', ''),
            'created_at': u.get('created_at', ''),
            'role':       u.get('role', 'user'),
            'locked':     u.get('locked', False)
        })
    log_action(admin_email, 'list_users', 'success')
    return True, result


def lock_user_account(admin_email: str,
                      target_email: str,
                      passphrase: str) -> tuple[bool, str]:
    """Chỉ admin/owner: khoá target_email (ngoại trừ owner)."""
    if not is_admin_or_owner(admin_email):
        log_action(admin_email, 'lock_user', 'fail: not_admin')
        return False, "Bạn không có quyền admin."
    ok, msg = verify_password(admin_email, passphrase)
    if not ok:
        log_action(admin_email, 'lock_user', 'fail: invalid_passphrase')
        return False, msg or "Passphrase admin không đúng."

    users = load_users()
    for u in users:
        if u['email'].lower() == target_email.lower():
            if u.get('role') == 'owner':
                log_action(admin_email, 'lock_user', 'fail: cannot_lock_owner')
                return False, "Không thể khóa tài khoản owner."
            u['locked'] = True
            save_users(users)
            log_action(admin_email, f'lock_user_{target_email}', 'success')
            return True, f"Đã khóa tài khoản {target_email}."
    log_action(admin_email, 'lock_user', f'fail: not_found - {target_email}')
    return False, f"Không tìm thấy user {target_email}."


def unlock_user_account(admin_email: str,
                        target_email: str,
                        passphrase: str) -> tuple[bool, str]:
    """Chỉ admin/owner: mở khoá target_email."""
    if not is_admin_or_owner(admin_email):
        log_action(admin_email, 'unlock_user', 'fail: not_admin')
        return False, "Bạn không có quyền admin."
    ok, msg = verify_password(admin_email, passphrase)
    if not ok:
        log_action(admin_email, 'unlock_user', 'fail: invalid_passphrase')
        return False, msg or "Passphrase admin không đúng."

    users = load_users()
    for u in users:
        if u['email'].lower() == target_email.lower():
            u['locked'] = False
            save_users(users)
            log_action(admin_email, f'unlock_user_{target_email}', 'success')
            return True, f"Đã mở khóa tài khoản {target_email}."
    log_action(admin_email, 'unlock_user', f'fail: not_found - {target_email}')
    return False, f"Không tìm thấy user {target_email}."


def promote_to_admin(admin_email: str,
                     target_email: str,
                     passphrase: str) -> tuple[bool, str]:
    """Chỉ owner: thăng cấp user → admin."""
    if not is_owner(admin_email):
        log_action(admin_email, 'promote_admin', 'fail: not_owner')
        return False, "Chỉ owner mới được phép."
    ok, msg = verify_password(admin_email, passphrase)
    if not ok:
        log_action(admin_email, 'promote_admin', 'fail: invalid_passphrase')
        return False, msg or "Passphrase owner không đúng."

    users = load_users()
    for u in users:
        if u['email'].lower() == target_email.lower():
            if u.get('role') == 'admin':
                log_action(admin_email, 'promote_admin',
                           f'fail: already_admin - {target_email}')
                return False, f"{target_email} đã là admin."
            if u.get('role') == 'owner':
                log_action(admin_email, 'promote_admin',
                           'fail: cannot_promote_owner')
                return False, "Không thể thăng cấp owner."
            u['role'] = 'admin'
            save_users(users)
            log_action(admin_email, f'promote_admin_{target_email}', 'success')
            return True, f"Đã thăng cấp {target_email} thành admin."
    log_action(admin_email, 'promote_admin',
               f'fail: not_found - {target_email}')
    return False, f"Không tìm thấy user {target_email}."


def demote_from_admin(admin_email: str,
                      target_email: str,
                      passphrase: str) -> tuple[bool, str]:
    """Chỉ owner: hạ cấp admin → user (không hạ cấp chính mình)."""
    if not is_owner(admin_email):
        log_action(admin_email, 'demote_admin', 'fail: not_owner')
        return False, "Chỉ owner mới được phép."
    if admin_email.lower() == target_email.lower():
        log_action(admin_email, 'demote_admin', 'fail: cannot_demote_self')
        return False, "Không thể hạ cấp chính mình."
    ok, msg = verify_password(admin_email, passphrase)
    if not ok:
        log_action(admin_email, 'demote_admin', 'fail: invalid_passphrase')
        return False, msg or "Passphrase owner không đúng."

    users = load_users()
    for u in users:
        if u['email'].lower() == target_email.lower():
            if u.get('role') != 'admin':
                log_action(admin_email, 'demote_admin',
                           f'fail: not_admin - {target_email}')
                return False, f"{target_email} không phải admin."
            u['role'] = 'user'
            save_users(users)
            log_action(admin_email, f'demote_admin_{target_email}', 'success')
            return True, f"Đã hạ cấp {target_email} thành user."
    log_action(admin_email, 'demote_admin',
               f'fail: not_found - {target_email}')
    return False, f"Không tìm thấy user {target_email}."


def view_system_logs(admin_email: str,
                     passphrase: str,
                     limit: int = 50) -> tuple[bool, list[dict] | str]:
    """Chỉ admin/owner: đọc file security.log và parse thành list các dict."""
    if not is_admin_or_owner(admin_email):
        log_action(admin_email, 'view_logs', 'fail: not_admin')
        return False, "Bạn không có quyền admin."
    ok, msg = verify_password(admin_email, passphrase)
    if not ok:
        log_action(admin_email, 'view_logs', 'fail: invalid_passphrase')
        return False, msg or "Passphrase không đúng."

    if not os.path.exists(LOG_FILE):
        log_action(admin_email, 'view_logs', 'fail: log_file_not_found')
        return False, "File log không tồn tại."

    with open(LOG_FILE, 'r', encoding='utf-8') as f:
        lines = f.readlines()

    recent = lines[-limit:] if len(lines) > limit else lines
    entries = []
    for line in recent:
        parts = line.strip().split(' | ')
        if len(parts) >= 4:
            entries.append({
                'timestamp': parts[0],
                'email':     parts[1],
                'action':    parts[2],
                'status':    parts[3]
            })

    log_action(admin_email, f'view_logs_{len(entries)}', 'success')
    return True, entries


def get_user_statistics(admin_email: str) -> tuple[bool, dict | str]:
    """Chỉ admin/owner: thống kê tổng, admin, owner, locked, tạo hôm nay/tuần/tháng."""
    if not is_admin_or_owner(admin_email):
        log_action(admin_email, 'get_stats', 'fail: not_admin')
        return False, "Bạn không có quyền admin."

    users = load_users()
    total       = len(users)
    admin_cnt   = sum(1 for u in users if u.get('role') == 'admin')
    owner_cnt   = sum(1 for u in users if u.get('role') == 'owner')
    locked_cnt  = sum(1 for u in users if u.get('locked', False))

    now       = datetime.now().date()
    week_ago  = now - timedelta(days=7)
    month_ago = now - timedelta(days=30)

    today_cnt = week_cnt = month_cnt = 0
    for u in users:
        try:
            d = datetime.fromisoformat(u.get('created_at', '')).date()
            if d == now:            today_cnt += 1
            if d >= week_ago:       week_cnt  += 1
            if d >= month_ago:      month_cnt += 1
        except:
            pass

    stats = {
        'total_users':  total,
        'admin_count':  admin_cnt,
        'owner_count':  owner_cnt,
        'locked_count': locked_cnt,
        'today_users':  today_cnt,
        'week_users':   week_cnt,
        'month_users':  month_cnt
    }

    log_action(admin_email, 'get_stats', 'success')
    return True, stats