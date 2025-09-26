# modules/utils/config.py
import os

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
DATA_DIR = os.path.join(BASE_DIR, 'data')

USERS_FILE          = os.path.join(DATA_DIR, 'users.json')
LOGIN_ATTEMPTS_FILE = os.path.join(DATA_DIR, 'login_attempts.json')
OTP_DATA_FILE       = os.path.join(DATA_DIR, 'otp_data.json')
RECOVERY_CODES_FILE = os.path.join(DATA_DIR, 'recovery_codes.json')
RECOVERY_KEYS_DIR = os.path.join(DATA_DIR, 'recovery_keys')
RSA_META_FILE       = os.path.join(DATA_DIR, 'rsa_keys.json')
LOG_FILE            = os.path.join(DATA_DIR, 'security.log')

KEY_DIR  = os.path.join(DATA_DIR, 'keys')
ENCRYPTED_DIR   = os.path.join(DATA_DIR, 'encrypted')
DECRYPTED_DIR  = os.path.join(DATA_DIR, 'decrypted')

# Kích thước block chia file (bytes)
BLOCK_SIZE = 1 * 1024 * 1024  

# Thời gian key RSA (ngày)
RSA_KEY_TTL_DAYS = 90