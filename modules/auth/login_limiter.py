# modules/auth/login_limiter.py
import os, json
from datetime import datetime, timedelta

from modules.utils.config import LOGIN_ATTEMPTS_FILE
from modules.utils.logger import log_action
from modules.auth.account    import load_users, save_users

def load_login_attempts():
    if not os.path.exists(LOGIN_ATTEMPTS_FILE):
        return {}
    return json.load(open(LOGIN_ATTEMPTS_FILE,'r',encoding='utf-8'))

def save_login_attempts(data):
    os.makedirs(os.path.dirname(LOGIN_ATTEMPTS_FILE), exist_ok=True)
    json.dump(data, open(LOGIN_ATTEMPTS_FILE,'w',encoding='utf-8'), indent=2, ensure_ascii=False)

def record_failed_login(email):
    data = load_login_attempts()
    now = datetime.now()
    rec = data.get(email, {'failed_attempts':0,'first_failed_time':None,'locked_until':None})
    rec['failed_attempts'] += 1
    if not rec['first_failed_time']:
        rec['first_failed_time'] = now.isoformat()
    if rec['failed_attempts']>=5:
        until = now + timedelta(minutes=5)
        rec['locked_until'] = until.isoformat()
        # mark locked in users.json
        users = load_users()
        for u in users:
            if u['email'].lower()==email.lower():
                u['locked'] = True
        save_users(users)
        log_action(email,'account_locked',f'until_{until.isoformat()}')
    else:
        log_action(email,'failed_login',f'attempt_{rec["failed_attempts"]}')
    data[email] = rec
    save_login_attempts(data)

def record_successful_login(email):
    data = load_login_attempts()
    if email in data:
        data[email] = {'failed_attempts':0,'first_failed_time':None,'locked_until':None}
        save_login_attempts(data)
    users = load_users()
    for u in users:
        if u['email'].lower()==email.lower():
            u['locked'] = False
    save_users(users)
    log_action(email,'successful_login','reset')

def is_account_locked(email):
    data = load_login_attempts().get(email,{})
    until = data.get('locked_until')
    if until:
        t = datetime.fromisoformat(until)
        if datetime.now()<t:
            rem = t - datetime.now()
            m,s = divmod(int(rem.total_seconds()),60)
            return True, f"{m:02d}:{s:02d}"
        # expired → reset
        record_successful_login(email)
    return False, None

def get_failed_attempts_info(email):
    rec = load_login_attempts().get(email,{'failed_attempts':0})
    return {
      'failed_attempts': rec['failed_attempts'],
      'remaining': max(0,5-rec['failed_attempts']),
      'locked': bool(rec.get('locked_until')),
      'until': rec.get('locked_until')
    }

# thêm force_unlock/get_all_locked nếu cần…