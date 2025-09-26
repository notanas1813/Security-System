# modules/auth/mfa.py

import os, json, secrets
import pyotp, qrcode, smtplib
from datetime import datetime, timedelta
from email.mime.text      import MIMEText
from email.mime.multipart import MIMEMultipart

from modules.utils.config import USERS_FILE, OTP_DATA_FILE, LOG_FILE
from modules.utils.logger import log_action
from modules.auth.account import load_users, save_users, verify_password

SMTP_SERVER    = "smtp.gmail.com"
SMTP_PORT      = 587
SENDER_EMAIL   = "nbao180204@gmail.com"
SENDER_PASSWORD = "aoyb qmeb vptx mxce"

def load_otp() -> dict:
    if not os.path.exists(OTP_DATA_FILE):
        return {}
    try:
        return json.load(open(OTP_DATA_FILE,'r',encoding='utf-8'))
    except:
        return {}

def save_otp(d: dict):
    os.makedirs(os.path.dirname(OTP_DATA_FILE), exist_ok=True)
    json.dump(d, open(OTP_DATA_FILE,'w',encoding='utf-8'), indent=2, ensure_ascii=False)

def generate_otp() -> str:
    return str(secrets.randbelow(1_000_000)).zfill(6)

def send_otp_email(email: str, otp: str) -> bool:
    try:
        msg = MIMEMultipart()
        msg['From']    = SENDER_EMAIL
        msg['To']      = email
        msg['Subject'] = "Mã OTP đăng nhập"
        msg.attach(MIMEText(f"Mã OTP của bạn: {otp}\nHết hạn sau 5 phút.", 'plain'))

        srv = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        srv.starttls()
        srv.login(SENDER_EMAIL, SENDER_PASSWORD)
        srv.sendmail(SENDER_EMAIL, email, msg.as_string())
        srv.quit()

        log_action(email, 'send_otp_email', 'success')
        return True
    except Exception as e:
        log_action(email, 'send_otp_email', f'fail: {e}')
        return False

def get_totp_secret(email: str) -> str|None:
    for u in load_users():
        if u['email'].lower() == email.lower():
            return u.get('totp_secret')
    return None

def create_totp_qr(email: str, secret: str) -> str:
    uri = pyotp.TOTP(secret).provisioning_uri(email, issuer_name="HCMUS Sec")
    img = qrcode.make(uri)
    qr_path = os.path.join(os.path.dirname(OTP_DATA_FILE),
                           f"{email.lower()}_totp_qr.png")
    os.makedirs(os.path.dirname(qr_path), exist_ok=True)
    img.save(qr_path)
    log_action(email, 'totp_qr_created', qr_path)
    return qr_path

def verify_otp(email: str, code: str) -> bool:
    d = load_otp()
    rec = d.get(email.lower())
    if not rec or datetime.now() > datetime.fromisoformat(rec['expiry']):
        log_action(email, 'verify_otp', 'fail: expired_or_missing')
        return False
    if rec['otp'] == code:
        log_action(email, 'verify_otp', 'success')
        del d[email.lower()]; save_otp(d)
        return True
    log_action(email, 'verify_otp', 'fail: wrong')
    return False

def verify_totp(email: str, code: str, secret: str) -> bool:
    ok = pyotp.TOTP(secret).verify(code)
    log_action(email, 'verify_totp', 'success' if ok else 'fail: wrong')
    return ok

def login_with_mfa(email: str, passphrase: str, mfa_type="email") -> tuple[bool,str]:
    ok, user = verify_password(email, passphrase)
    if not ok:
        return False, "Email hoặc passphrase không đúng."
    if user.get('locked', False):
        return False, "Tài khoản đang bị khóa."

    if mfa_type == "email":
        otp = generate_otp()
        expiry = datetime.now() + timedelta(minutes=5)
        d = load_otp()
        d[email.lower()] = {'otp':otp, 'expiry':expiry.isoformat()}
        save_otp(d)
        send_otp_email(email, otp)
        return True, f"Đã gửi OTP đến {email}."

    # TOTP
    secret = get_totp_secret(email)
    if not secret:
        secret = pyotp.random_base32()
        users = load_users()
        for u in users:
            if u['email'].lower() == email.lower():
                u['totp_secret'] = secret
        save_users(users)
        qr = create_totp_qr(email, secret)
        return True, f"Chưa có TOTP. Quét QR tại {qr}."
    else:
        return True, "TOTP đã sẵn sàng. Nhập mã từ Authenticator."

def complete_mfa_verification(email: str, code: str, mfa_type="email") -> tuple[bool,str]:
    if mfa_type == "email":
        if verify_otp(email, code):
            log_action(email, 'login', 'success')
            return True, "Đăng nhập thành công!"
        return False, "OTP sai hoặc hết hạn."

    secret = get_totp_secret(email)
    if secret and verify_totp(email, code, secret):
        log_action(email, 'login', 'success')
        return True, "Đăng nhập thành công!"
    return False, "TOTP không đúng."