# modules/utils/logger.py
import os, datetime
from modules.utils.config import LOG_FILE

def log_action(email: str, action: str, status: str, target: str = ''):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    with open(LOG_FILE, 'a', encoding='utf-8') as f:
        f.write(f"{datetime.datetime.now().isoformat()} | {email} | {action} | {status} | {target}\n")