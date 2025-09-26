# Modules package for HCMUS Security System
# Version: 1.0.0
# Author: HCMUS Computer Security Project

"""
HCMUS Security System Modules

Available modules:
- register: User registration with password hashing
- mfa_login_confirmation: Multi-factor authentication (OTP/TOTP)
- key_management: RSA key generation and management
- crypto_modules: Cryptographic operations (encryption, decryption, signing)
- utils: Utility functions for logging, file handling, and configuration

Usage:
    from modules.register import register_user
    from modules.mfa_login_confirmation import login_with_mfa
"""

__version__ = "1.0.0"
__author__ = "HCMUS Computer Security Project" 