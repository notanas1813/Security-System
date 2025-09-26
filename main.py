#!/usr/bin/env python3
# main.py — Giao diện tiếng Việt

import sys
import os
import json
from getpass import getpass

from modules.auth.account            import (
    register_user,
    update_user_info,
    change_passphrase,
    delete_account,
    get_user_info,
)
from modules.auth.login_limiter      import (
    is_account_locked,
    record_failed_login,
    record_successful_login
)
from modules.auth.login              import login
from modules.auth.mfa                import complete_mfa_verification

from modules.key_management.rsa_keys       import (
    create_rsa_keypair,
    load_metadata,
    is_key_expired,
    renew_key_if_needed,
    remove_keypair,
)
from modules.key_management.key_status     import get_key_status
from modules.key_management.public_key_search import find_public_key
from modules.key_management.qr_public_key import (
    create_qr_code_for_public_key,
    read_qr_code_from_file
)

from modules.crypto_module.file_encrypt  import encrypt_file
from modules.crypto_module.file_decrypt  import decrypt_file
from modules.crypto_module.signature     import sign_file, verify_signature

from modules.auth.recovery_system   import generate_recovery_code
from modules.key_management.recovery_keys import create_recovery_backup

# Chức năng đổi passphrase
from modules.auth.recovery_system    import reset_password_with_recovery
# Chức năng recover private-key
from modules.key_management.recovery_keys import recover_private_key

from modules.auth.recovery_system    import delete_recovery_code, delete_recovery_backup

from modules.auth.admin_management import (
     is_admin_or_owner,
     is_owner,
     list_all_users,
     lock_user_account,
     unlock_user_account,
     promote_to_admin,
     demote_from_admin,
     view_system_logs,
     get_user_statistics
)

from modules.utils.config   import KEY_DIR
from modules.utils.logger   import log_action


def menu_chinh() -> str:
    print("""
=== MENU CHÍNH ===
1. Đăng ký
2. Đăng nhập
3. Quên mật khẩu
4. Thoát
""")
    return input("Lựa chọn> ").strip()


def menu_dashboard(user_email: str) -> str:
    """
    Vẽ menu chính, chỉ show '14. Quản trị hệ thống' nếu user_email
    là admin hoặc owner.
    """
    print(f"""
=== BẢNG ĐIỀU KHIỂN ===

▶ Quản lý Khóa RSA
  1. Tạo cặp khóa RSA
  2. Hiển thị trạng thái khóa
  3. Gia hạn khóa (nếu hết hạn)
  4. Xóa cặp khóa RSA
  5. QR Code Public Key

▶ Mã hóa / Giải mã
  6. Mã hóa file
  7. Giải mã file

▶ Chữ ký số
  8. Ký file
  9. Xác thực chữ ký

▶ Quản lý Tài khoản
 10. Xem thông tin tài khoản
 11. Cập nhật thông tin tài khoản
 12. Đổi passphrase
 13. Xóa tài khoản""")

    # Chỉ hiển thị mục 14 nếu có quyền
    if is_admin_or_owner(user_email):
        print(" 14. Quản trị hệ thống")

    print("  0. Đăng xuất\n")
    return input("Lựa chọn> ").strip()


def handle_register() -> tuple[bool, str, str]:
    """
    Trả về: (ok, email, passphrase).
    Nếu ok=True, đã register xong và đã backup private-key.
    """
    print("=== Đăng ký tài khoản ===")
    email   = input("Email: ").strip()
    name    = input("Họ và tên: ").strip()
    dob     = input("Ngày sinh (YYYY-MM-DD): ").strip()
    phone   = input("Số điện thoại: ").strip()
    address = input("Địa chỉ: ").strip()
    pw      = getpass("Passphrase: ")

    # 1) Tạo user
    ok, msg = register_user(email, name, dob, phone, address, pw)
    print(msg)
    if not ok:
        return False, "", ""

    # 2) Tự động tạo recovery code (hiển thị 1 lần)
    ok1, msg1 = generate_recovery_code(email)
    print(msg1)
    code = msg1.split()[2]
    
    ok2, backup_path = create_recovery_backup(email, pw, code)
    if ok2:
        print("✅ Backup private key (encoded by recovery code) lưu tại:", backup_path)
    else:
        print("❌ Lỗi khi backup private key:", backup_path)
        # Dù backup thất bại, user vẫn có account, nhưng không thể khôi phục key
    return True, email, pw

def handle_login() -> str | None:
    print("=== Đăng nhập ===")
    email = input("Email: ").strip()
    pw    = getpass("Passphrase: ")

    locked, rem = is_account_locked(email)
    if locked:
        print(f"Tài khoản đã khóa. Thử lại sau {rem}.")
        return None

    print("Chọn MFA:\n 1. Email OTP\n 2. TOTP Authenticator")
    mfa_type = 'email' if input("Lựa chọn> ").strip() == '1' else 'totp'

    ok, msg = login(email, pw, mfa_type)
    print(msg)
    if not ok:
        record_failed_login(email)
        return None

    code = input("Nhập mã xác thực> ").strip()
    ok2, msg2 = complete_mfa_verification(email, code, mfa_type)
    print(msg2)
    if not ok2:
        record_failed_login(email)
        return None

    record_successful_login(email)
    return email


def handle_create_rsa(user_email: str):
    print("=== Tạo cặp khóa RSA ===")
    pw = getpass("Passphrase để mã hoá private key: ")
    pub_path, priv_path = create_rsa_keypair(user_email, pw)
    print(f"Public key: {pub_path}\nPrivate key (đã mã hoá): {priv_path}")


def handle_show_key_status(user_email: str):
    print("=== Trạng thái khóa RSA ===")
    meta = load_metadata(user_email)
    if not meta:
        print("Chưa có keypair.")
        return
    expired = is_key_expired(user_email)
    print(f"Đã tạo: {meta['created_at']}")
    print(f"Hết hạn: {meta['expires_at']}")
    print("Tình trạng:", "Đã hết hạn" if expired else "Còn hạn")


def handle_renew_key(user_email: str):
    print("=== Gia hạn khóa RSA ===")
    pw = getpass("Passphrase hiện tại: ")
    pub, priv = renew_key_if_needed(user_email, pw)
    print(f"Khóa mới đã được tạo.\nPublic: {pub}\nPrivate: {priv}")


def handle_delete_rsa(user_email: str):
    print("=== Xóa cặp khóa RSA ===")
    ok = remove_keypair(user_email)
    print("Đã xóa keypair." if ok else "Không tìm thấy keypair.")


def handle_qr_public_key(user_email):
    print("1. Xuất QR public key")
    print("2. Đọc QR và import public key")
    ch = input("Lựa chọn> ").strip()
    if ch=='1':
        ok, path = create_qr_code_for_public_key(user_email)
        print(ok and f"Đã lưu QR: {path}" or path)
    elif ch=='2':
        fp = input("Đường dẫn file QR> ").strip()
        ok, res = read_qr_code_from_file(fp, user_email)
        if ok:
            print("Import thành công:", res)
        else:
            print("Lỗi:", res)
    else:
        print("Không hợp lệ.")


def handle_file_encrypt(user_email: str):
    print("=== MÃ HÓA FILE ===")
    src  = input("Đường dẫn file nguồn> ").strip()
    recv = input("Email người nhận> ").strip()
    print("Chọn cách xuất:")
    print("  1. Gộp session-key vào 1 file .enc")
    print("  2. Tách thành 2 file: .enc (tag+ct) & .key (meta+enc_skey)")
    mode = input("Lựa chọn [1/2]> ").strip()
    merged = (mode == '1')

    try:
        res = encrypt_file(src, user_email, recv, merged=merged)
        # encrypt_file trả về:
        #   - merged=True  →  đường dẫn .enc (string)
        #   - merged=False →  tuple(ct_path, key_path)
        if merged:
            print(f"✅ Mã hóa thành công, file .enc lưu tại: {res}")
        else:
            ct, key = res
            print("✅ Mã hóa thành công:")
            print(f"  • Ciphertext: {ct}")
            print(f"  • Key file  : {key}")
    except Exception as e:
        print("❌ Lỗi khi mã hóa:", e)


def handle_file_decrypt(user_email: str):
    print("=== GIẢI MÃ FILE ===")
    print("Chọn loại đầu vào:")
    print("  1. File .enc gộp")
    print("  2. File .enc + file .key tách")
    mode = input("Lựa chọn [1/2]> ").strip()
    merged   = (mode == '1')
    enc_path = input("Đường dẫn file .enc> ").strip()
    key_file = None
    if not merged:
        key_file = input("Đường dẫn file .key> ").strip()

    pw = getpass("Passphrase private key> ")

    try:
        # Chú ý: decrypt_file signature gốc là
        #    decrypt_file(enc_path, user_email, passphrase, merged, key_file_path)
        out_path, meta = decrypt_file(
            enc_path,
            user_email,
            pw,
            merged=merged,
            key_file_path=key_file
        )
        print(f"✅ Giải mã thành công, file gốc lưu tại: {out_path}")
    except Exception as e:
        print("❌ Lỗi khi giải mã:", e)


def handle_sign_file(user_email: str):
    print("=== KÝ FILE ===")
    src = input("Đường dẫn file cần ký> ").strip()
    # Bắt buộc hỏi passphrase để giải mã private key
    pw  = getpass("Passphrase private key của bạn> ")
    try:
        sig_path = sign_file(src, user_email, pw)
        print(f"✅ Đã tạo chữ ký: {sig_path}")
    except Exception as e:
        print(f"❌ Lỗi khi ký file: {e}")

def handle_verify_signature(user_email: str):
    print("=== XÁC THỰC CHỮ KÝ ===")
    src = input("Đường dẫn file gốc> ").strip()
    sig = input("Đường dẫn file chữ ký (.sig)> ").strip()
    try:
        ok, signers = verify_signature(src, sig)
        if ok:
            print("✅ Xác thực thành công! Người ký:", ", ".join(signers))
        else:
            print("❌ Xác thực thất bại. Không tìm được public key phù hợp.")
    except Exception as e:
        print(f"❌ Lỗi khi xác thực chữ ký: {e}")


def handle_view_account_info(user_email: str):
    print("=== Thông tin tài khoản ===")
    info = get_user_info(user_email)
    if info:
        for k, v in info.items():
            print(f"{k.capitalize():12}: {v}")
    else:
        print("Không tìm thấy thông tin.")


def handle_update_user_info(user_email: str):
    print("=== Cập nhật thông tin ===")
    old_pw = getpass("Passphrase hiện tại> ")
    new_name    = input("Họ và tên (Enter để giữ nguyên)> ").strip()
    new_dob     = input("Ngày sinh (YYYY-MM-DD)> ").strip()
    new_phone   = input("SĐT> ").strip()
    new_address = input("Địa chỉ> ").strip()
    new_info = {}
    if new_name:    new_info['name']    = new_name
    if new_dob:     new_info['dob']     = new_dob
    if new_phone:   new_info['phone']   = new_phone
    if new_address: new_info['address'] = new_address
    ok, msg = update_user_info(user_email, old_pw, new_info)
    print(msg)


def handle_change_passphrase(user_email: str):
    print("=== Đổi passphrase ===")
    old_pw = getpass("Passphrase hiện tại> ")
    new_pw = getpass("Passphrase mới> ")
    ok, msg = change_passphrase(user_email, old_pw, new_pw)
    print(msg)


def handle_delete_account(user_email: str):
    print("=== Xóa tài khoản ===")
    pw = getpass("Passphrase> ")
    ok, msg = delete_account(user_email, pw)
    print(msg)
    if ok:
        delete_recovery_code(user_email)
        delete_recovery_backup(user_email)
        print("Đã xóa tài khoản, chương trình sẽ thoát.")
        sys.exit(0)

def handle_account_recovery():
    print("=== KHÔI PHỤC TÀI KHOẢN ===")
    email  = input("Email> ").strip()
    code   = input("Recovery code> ").strip()
    new_pw = getpass("Passphrase mới> ")

    ok, msg = reset_password_with_recovery(email, code, new_pw)
    print(msg)
    if not ok:
        return

    ok2, out = recover_private_key(email, code, new_pw)
    print(ok2
          and f"✅ Đã recover & cập nhật private key tại: {out}"
          or  f"❌ Lỗi recover private key: {out}")

def handle_manage_menu(user_email: str):
    owner = is_owner(user_email)
    while True:
        print("""
=== QUẢN TRỊ HỆ THỐNG ===
 1. Xem danh sách tài khoản
 2. Khóa tài khoản
 3. Mở khóa tài khoản
 4. Xem log hệ thống
 5. Thống kê user""")
        if owner:
            print(" 6. Thăng cấp user → admin")
            print(" 7. Hạ cấp admin → user")
        print(" 0. Quay lại")

        ch = input("Chọn> ").strip()
        if ch == '1':
            ok, data = list_all_users(user_email)
            if not ok: print("❌", data)
            else:
                print(f"{'Email':30}{'Role':8}{'Locked':7}{'Ngày tạo'}")
                for u in data:
                    lock = "🔒" if u['locked'] else "✔"
                    print(f"{u['email']:30}{u['role']:8}{lock:7}{u['created_at']}")
        elif ch in ('2','3'):
            target = input("Email target> ").strip()
            pw     = getpass("Passphrase quản trị> ")
            fn     = lock_user_account if ch=='2' else unlock_user_account
            ok, msg = fn(user_email, target, pw)
            print(ok and "✅ "+msg or "❌ "+msg)
        elif ch == '4':
            pw = getpass("Passphrase quản trị> ")
            ok, logs = view_system_logs(user_email, pw)
            if not ok: print("❌", logs)
            else:
                for e in logs:
                    print(
                      f"{e['timestamp']} | {e['email']} | "
                      f"{e['action']} | {e['status']}"
                    )
        elif ch == '5':
            ok, stats = get_user_statistics(user_email)
            if not ok: print("❌", stats)
            else:
                print("Thống kê user:")
                for k,v in stats.items():
                    print(f" - {k}: {v}")
        elif owner and ch == '6':
            target = input("Email target> ").strip()
            pw     = getpass("Passphrase quản trị> ")
            ok, msg = promote_to_admin(user_email, target, pw)
            print(ok and "✅ "+msg or "❌ "+msg)
        elif owner and ch == '7':
            target = input("Email target> ").strip()
            pw     = getpass("Passphrase quản trị> ")
            ok, msg = demote_from_admin(user_email, target, pw)
            print(ok and "✅ "+msg or "❌ "+msg)
        elif ch == '0':
            break
        else:
            print("Lựa chọn không hợp lệ.")

def main():
    while True:
        choice = menu_chinh()
        if choice == '1':
            ok, email, passphrase = handle_register()
            if ok:
                print("🎉 Đăng ký & backup private-key hoàn tất. HÃY LƯU LẠI RECOVERY CODE!!!")
        elif choice == '2':
            user = handle_login()
            if not user:
                continue
            # Vào dashboard sau khi đăng nhập thành công
            while True:
                ch = menu_dashboard(user)
                if ch == '1':  handle_create_rsa(user)
                elif ch == '2':  handle_show_key_status(user)
                elif ch == '3':  handle_renew_key(user)
                elif ch == '4':  handle_delete_rsa(user)
                elif ch == '5':  handle_qr_public_key(user)
                elif ch == '6':  handle_file_encrypt(user)
                elif ch == '7':  handle_file_decrypt(user)
                elif ch == '8':  handle_sign_file(user)
                elif ch == '9':  handle_verify_signature(user)
                elif ch == '10': handle_view_account_info(user)
                elif ch == '11': handle_update_user_info(user)
                elif ch == '12': handle_change_passphrase(user)
                elif ch == '13': handle_delete_account(user)
                elif ch == '14' and is_admin_or_owner(user):
                    handle_manage_menu(user)
                elif ch == '0':
                    print("Đã đăng xuất.")
                    break
                else:
                    print("Lựa chọn không hợp lệ.")
        elif choice == '3':
            handle_account_recovery()       
        elif choice == '4':
            print("Tạm biệt!")
            sys.exit(0)
        else:
            print("Lựa chọn không hợp lệ.")


if __name__ == "__main__":
    main()