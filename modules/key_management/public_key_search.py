# modules/key_management/public_key_search.py
import os
from modules.key_management.rsa_keys import load_metadata
from modules.utils.config import KEY_DIR

def find_public_key(email: str):
    md = load_metadata(email)
    if not md: 
        return None
    path = os.path.join(KEY_DIR, md['pub_file'])
    return path