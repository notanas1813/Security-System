# modules/key_management/key_status.py
from datetime import datetime
from modules.key_management.rsa_keys import load_metadata, renew_key_if_needed, is_key_expired
from modules.utils.logger import log_action

def get_key_status(email: str):
    md = load_metadata(email)
    if not md:
        return {'status':'missing'}
    now = datetime.now()
    exp = datetime.fromisoformat(md['expires_at'])
    delta = (exp - now).days
    status = 'ok'
    if delta < 0:
        status = 'expired'
    elif delta < 7:
        status = 'near_expiry'
    return {
      'created_at': md['created_at'],
      'expires_at': md['expires_at'],
      'status': status
    }

def format_key_status(email: str) -> str:
    """
    Trả về chuỗi multi-line đẹp để in ra console.
    """
    st = get_key_status(email)
    # Chưa có key
    if st.get('status') == 'missing':
        return "🔑 Bạn chưa có khóa RSA. Vui lòng tạo khóa trước khi sử dụng."
    # parse ngày
    created = datetime.fromisoformat(st['created_at']) \
                      .strftime("%d/%m/%Y %H:%M:%S")
    expires = datetime.fromisoformat(st['expires_at']) \
                      .strftime("%d/%m/%Y %H:%M:%S")
    days_left = (datetime.fromisoformat(st['expires_at']) - datetime.now()).days
    # map status sang chuỗi tiếng Việt
    status_map = {
        'ok':         'Hoạt động',
        'near_expiry':'Sắp hết hạn',
        'expired':    'Đã hết hạn'
    }
    return (
        f"🗂 Trạng thái khóa RSA của {email}:\n"
        f"  • Ngày tạo    : {created}\n"
        f"  • Ngày hết hạn: {expires}  ({days_left} ngày còn lại)\n"
        f"  • Trạng thái  : {status_map[st['status']]}\n"
    )

def renew_key(email: str, passphrase: str):
    pub, priv = renew_key_if_needed(email, passphrase)
    log_action(email, 'key_renew', 'success')
    return pub, priv