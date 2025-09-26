# modules/auth/login.py

from modules.auth.mfa import login_with_mfa

def login(email: str, passphrase: str, mfa_type="email") -> tuple[bool,str]:
    """
    Pha 1: xác thực credentials + trigger OTP/TOTP.
    """
    return login_with_mfa(email, passphrase, mfa_type)