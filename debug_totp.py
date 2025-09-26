#!/usr/bin/env python3
"""
Debug script để kiểm tra TOTP
Chạy: python debug_totp.py
"""

import pyotp
import qrcode
import os
from modules.mfa_login_confirmation import load_users, get_totp_secret

def debug_totp(email):
    print(f"=== DEBUG TOTP CHO EMAIL: {email} ===")
    
    # Kiểm tra user có tồn tại không
    users = load_users()
    user_found = False
    for user in users:
        if user['email'].lower() == email.lower():
            user_found = True
            print(f"✅ Tìm thấy user: {user['name']}")
            break
    
    if not user_found:
        print("❌ Không tìm thấy user với email này")
        return
    
    # Lấy TOTP secret
    totp_secret = get_totp_secret(email)
    if not totp_secret:
        print("❌ User chưa có TOTP secret")
        print("Hãy đăng nhập và chọn TOTP để tạo secret mới")
        return
    
    print(f"✅ TOTP Secret: {totp_secret}")
    
    # Tạo TOTP object
    totp = pyotp.TOTP(totp_secret)
    
    # Tạo QR code
    provisioning_uri = totp.provisioning_uri(email, issuer_name="HCMUS Security System")
    print(f"✅ Provisioning URI: {provisioning_uri}")
    
    # Tạo QR code image
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    qr_filename = f'debug_{email}_totp_qr.png'
    img.save(qr_filename)
    print(f"✅ QR Code đã lưu: {qr_filename}")
    
    # Sinh mã TOTP hiện tại
    current_totp = totp.now()
    print(f"✅ Mã TOTP hiện tại: {current_totp}")
    
    # Test verify
    print("\n=== TEST VERIFY ===")
    test_code = input("Nhập mã TOTP từ Google Authenticator để test: ")
    
    if totp.verify(test_code):
        print("✅ Verify thành công!")
    else:
        print("❌ Verify thất bại!")
        print("Có thể do:")
        print("- Thời gian không đồng bộ")
        print("- Secret key không đúng")
        print("- Mã TOTP đã hết hạn")

if __name__ == "__main__":
    print("=== DEBUG TOTP ===")
    email = input("Nhập email để debug TOTP: ")
    debug_totp(email) 