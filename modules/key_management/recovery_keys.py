import os, secrets, base64
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher     import AES
from modules.key_management.rsa_keys import load_metadata
from modules.utils.config             import KEY_DIR, RECOVERY_KEYS_DIR
from modules.utils.logger             import log_action

def create_recovery_backup(email: str, passphrase: str, recovery_code: str):
    """
    1) Giải mã private-key hiện tại bằng passphrase
    2) Mã hoá lại private-key đó bằng recovery_code
    3) Lưu file: RECOVERY_KEYS_DIR/<email>_recovery.key
    """
    md = load_metadata(email)
    if not md:
        return False, "Chưa có key RSA để backup."
    # đọc file private-enc
    priv_enc = os.path.join(KEY_DIR, md['priv_file'])
    raw = open(priv_enc,'rb').read()
    salt, nonce, tag, ct = raw[:16], raw[16:32], raw[32:48], raw[48:]
    # derive AES từ passphrase
    aes_key = PBKDF2(passphrase, salt, dkLen=32, count=100_000)
    cipher  = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    try:
        priv_pem = cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        return False, f"Giải mã private key thất bại: {e}"

    # Mã hoá bằng recovery_code
    rec_salt = secrets.token_bytes(16)
    rec_key  = PBKDF2(recovery_code, rec_salt, dkLen=32, count=100_000)
    rec_cipher = AES.new(rec_key, AES.MODE_GCM)
    rec_ct, rec_tag = rec_cipher.encrypt_and_digest(priv_pem)

    os.makedirs(RECOVERY_KEYS_DIR, exist_ok=True)
    out = os.path.join(RECOVERY_KEYS_DIR, f"{email}_recovery.key")
    with open(out,'wb') as f:
        f.write(rec_salt + rec_cipher.nonce + rec_tag + rec_ct)

    log_action(email, 'create_recovery_backup', 'success')
    return True, out


def recover_private_key(email: str, recovery_code: str, new_passphrase: str):
    """
    1) Đọc backup file, giải mã bằng recovery_code → raw private PEM
    2) Mã hoá lại bằng new_passphrase → ghi đè vào file private-enc
    """
    path = os.path.join(RECOVERY_KEYS_DIR, f"{email}_recovery.key")
    if not os.path.exists(path):
        return False, "Không tìm thấy file recovery backup."
    raw = open(path,'rb').read()
    salt, nonce, tag, ct = raw[:16], raw[16:32], raw[32:48], raw[48:]
    rec_key = PBKDF2(recovery_code, salt, dkLen=32, count=100_000)
    cipher  = AES.new(rec_key, AES.MODE_GCM, nonce=nonce)
    try:
        priv_pem = cipher.decrypt_and_verify(ct, tag)
    except Exception as e:
        return False, f"Recovery code không đúng hoặc file hỏng: {e}"

    # Mã hoá lại bằng passphrase mới
    new_salt = secrets.token_bytes(16)
    new_key  = PBKDF2(new_passphrase, new_salt, dkLen=32, count=100_000)
    new_cipher = AES.new(new_key, AES.MODE_GCM)
    new_ct, new_tag = new_cipher.encrypt_and_digest(priv_pem)

    md = load_metadata(email)
    out_priv = os.path.join(KEY_DIR, md['priv_file'])
    with open(out_priv,'wb') as f:
        f.write(new_salt + new_cipher.nonce + new_tag + new_ct)

    log_action(email, 'recover_private_key', 'success')
    return True, out_priv