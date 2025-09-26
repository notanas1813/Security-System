# gui_app.py

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
import json
import shutil
import os

# --- IMPORT CÁC MODULE TỪ PROJECT ---
from modules.auth.account            import (
    register_user, update_user_info, change_passphrase,
    delete_account, get_user_info, load_users
)
from modules.auth.login_limiter      import (
    is_account_locked, record_failed_login, record_successful_login
)
from modules.auth.login              import login
from modules.auth.mfa                import complete_mfa_verification, login_with_mfa
from modules.auth.recovery_system    import (
    generate_recovery_code,
    reset_password_with_recovery,
    delete_recovery_code,
    delete_recovery_backup
)
from modules.key_management.recovery_keys import (
    create_recovery_backup,
    recover_private_key
)
from modules.key_management.rsa_keys import (
    create_rsa_keypair, load_metadata,
    is_key_expired, renew_key_if_needed,
    remove_keypair
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
from modules.auth.admin_management import (
    is_admin_or_owner, is_owner,
    list_all_users, lock_user_account,
    unlock_user_account, promote_to_admin,
    demote_from_admin, view_system_logs,
    get_user_statistics
)
# ------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Computer Security GUI")
        self.geometry("600x600")
        self.resizable(False, False)

        self.current_user = None
        self.current_role = None

        container = ttk.Frame(self)
        container.pack(fill="both", expand=True)
        self.frames = {}

        # Đăng ký 4 Frame: Login, Register, Recovery, Dashboard
        for F in (LoginFrame, RegisterFrame, RecoveryFrame, DashboardFrame):
            frame = F(container, self)
            self.frames[F] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.show_frame(LoginFrame)

    def show_frame(self, cls):
        frame = self.frames[cls]
        # gọi on_show nếu có (Dashboard để cập nhật admin tab)
        if hasattr(frame, "on_show"):
            frame.on_show()
        frame.tkraise()


class LoginFrame(ttk.Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        self.ctrl = controller

        ttk.Label(self, text="📧 Email").pack(pady=(60,5))
        self.email_entry = ttk.Entry(self); self.email_entry.pack()

        ttk.Label(self, text="🔒 Passphrase").pack(pady=(20,5))
        self.pw_entry = ttk.Entry(self, show="*"); self.pw_entry.pack()

        ttk.Button(self, text="Login", command=self.do_login)\
            .pack(pady=(30,10))

        ttk.Button(self, text="Đăng ký",
                   command=lambda: controller.show_frame(RegisterFrame))\
            .pack(pady=(5,2))
        ttk.Button(self, text="Quên mật khẩu",
                   command=lambda: controller.show_frame(RecoveryFrame))\
            .pack()

    def do_login(self):
        email = self.email_entry.get().strip()
        pw    = self.pw_entry.get().strip()

        if not email or not pw:
            return messagebox.showerror("Error", "Email và Passphrase không được để trống.")

        locked, rem = is_account_locked(email)
        if locked:
            return messagebox.showerror("Locked", f"Tài khoản bị khóa. Thử lại sau {rem}.")

        # 1) Popup chọn MFA
        mfa = self.ask_mfa_method()
        if mfa is None:
            return  # user Cancel → hủy login

        # 2) Gửi OTP/TOTP
        ok, msg = login(email, pw, mfa)
        if not ok:
            record_failed_login(email)
            return messagebox.showerror("Login failed", msg)

        # 3) Nếu TOTP và mới sinh QR thì hiển thị QR
        if mfa == "totp" and msg.startswith("Chưa có TOTP"):
            # msg = "Chưa có TOTP. Quét QR tại /path/to/qr.png"
            qr_path = msg.split("Quét QR tại", 1)[1].strip().rstrip(".")
            self._show_qr_dialog(qr_path)
        else:
            # Email OTP hoặc TOTP đã sẵn sàng
            messagebox.showinfo("MFA Step", msg)

        # 4) Popup nhập mã
        code = self.ask_mfa_code()
        if code is None:
            return  # user Cancel → hủy login

        ok2, msg2 = complete_mfa_verification(email, code, mfa)
        if not ok2:
            record_failed_login(email)
            return messagebox.showerror("MFA failed", msg2)

        record_successful_login(email)
        self.ctrl.current_user = email
        messagebox.showinfo("Success", "Đăng nhập thành công!")
        self.ctrl.show_frame(DashboardFrame)


    def _show_qr_dialog(self, qr_path: str):
        """
        Hiển thị QR Code (file PNG) trong 1 dialog để user scan.
        Khi user bấm OK, cửa sổ đóng và flow sẽ tiếp tục.
        """
        win = tk.Toplevel(self)
        win.title("Quét QR Code TOTP")
        win.transient(self)
        win.grab_set()

        # Load ảnh QR (PhotoImage hỗ trợ PNG)
        img = tk.PhotoImage(file=qr_path)
        lbl = tk.Label(win, image=img)
        lbl.image = img     # giữ reference tránh bị thu gom
        lbl.pack(padx=10, pady=10)

        btn = ttk.Button(win, text="OK, tôi đã quét xong", command=win.destroy)
        btn.pack(pady=(0,10))

        win.wait_window()   # chặn tới khi user đóng dialog

    def ask_mfa_method(self) -> str|None:
        """
        Hiện popup modal cho user chọn Email OTP hoặc TOTP.
        Trả về "email", "totp" hoặc None nếu Cancel/đóng cửa sổ.
        """
        parent = self.winfo_toplevel()
        popup = tk.Toplevel(parent)
        popup.title("Chọn phương thức MFA")
        popup.transient(parent)
        popup.grab_set()
        popup.resizable(False, False)

        choice = {"mfa": None}

        ttk.Label(popup, text="Chọn MFA:", padding=10).pack()
        btns = ttk.Frame(popup); btns.pack(pady=5)
        ttk.Button(btns, text="Email OTP", width=20,
                   command=lambda: (choice.update(mfa="email"), popup.destroy())
                  ).pack(pady=3)
        ttk.Button(btns, text="TOTP Authenticator", width=20,
                   command=lambda: (choice.update(mfa="totp"), popup.destroy())
                  ).pack(pady=3)
        ttk.Separator(popup).pack(fill="x", pady=5)
        ttk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=(0,10))

        popup.protocol("WM_DELETE_WINDOW", popup.destroy)
        popup.wait_window()
        return choice["mfa"]


    def ask_mfa_code(self) -> str|None:
        """
        Hiện popup modal để nhập mã OTP/TOTP.
        Trả về mã hoặc None nếu Cancel.
        """
        parent = self.winfo_toplevel()
        popup = tk.Toplevel(parent)
        popup.title("Nhập mã xác thực")
        popup.transient(parent)
        popup.grab_set()
        popup.resizable(False, False)

        var = {"code": None}

        ttk.Label(popup, text="Nhập mã bạn đã nhận:", padding=10).pack()
        entry = ttk.Entry(popup); entry.pack(pady=5, padx=10)

        def on_submit():
            var["code"] = entry.get().strip()
            popup.destroy()

        btn_frame = ttk.Frame(popup); btn_frame.pack(pady=5)
        ttk.Button(btn_frame, text="Xác nhận", command=on_submit).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Cancel",    command=popup.destroy).pack(side="left", padx=5)

        popup.protocol("WM_DELETE_WINDOW", popup.destroy)
        popup.wait_window()
        return var["code"]


class RegisterFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent)
        self.ctrl = controller

        ttk.Label(self, text="✍️ Đăng ký tài khoản").pack(pady=5)
        self.fields = {}
        for label in ("Email", "Họ và tên", "Ngày sinh (YYYY-MM-DD)",
                      "Số điện thoại", "Địa chỉ", "Passphrase"):
            ttk.Label(self, text=label).pack(anchor="w", padx=20, pady=2)
            ent = ttk.Entry(self, show="*" if "Passphrase" in label else None)
            ent.pack(fill="x", padx=20)
            self.fields[label] = ent

        ttk.Button(self, text="Submit", command=self.do_register).pack(pady=10)
        ttk.Button(self, text="← Back to Login",
                   command=lambda: controller.show_frame(LoginFrame)).pack()

    def do_register(self):
        f     = self.fields
        email = f["Email"].get().strip()
        name  = f["Họ và tên"].get().strip()
        dob   = f["Ngày sinh (YYYY-MM-DD)"].get().strip()
        phone = f["Số điện thoại"].get().strip()
        addr  = f["Địa chỉ"].get().strip()
        pw    = f["Passphrase"].get().strip()

        if not email or not name or not pw:
            return messagebox.showerror("Error", "Email, Họ tên, Passphrase bắt buộc.")

        # 1) Đăng ký user
        ok, msg = register_user(email, name, dob, phone, addr, pw)
        messagebox.showinfo("Đăng ký", msg)
        if not ok:
            return

        # 1) Sinh recovery code
        ok1, rec_msg = generate_recovery_code(email)
        if not ok1:
            return messagebox.showerror("Lỗi khôi phục", rec_msg)

        # 2) Tách đúng code từ dòng đầu
        first_line = rec_msg.splitlines()[0]
        code = first_line.split(":", 1)[1].strip()
        messagebox.showinfo("Mã khôi phục", f"Mã khôi phục của bạn:\n{code}")

        # 3) Tạo backup key (không hiển thị path)
        create_recovery_backup(
            email,
            pw.encode('utf-8'),
            code.encode('utf-8')
        )

        # 4) Thông báo thành công và về Login
        messagebox.showinfo("Thành công", "🎉 Đăng ký thành công!")
        self.ctrl.show_frame(LoginFrame)


class RecoveryFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent)
        self.ctrl = controller

        ttk.Label(self, text="🔄 Khôi phục tài khoản").pack(pady=5)
        self.email_ent = self._add_field("Email:")
        self.code_ent  = self._add_field("Recovery code:")
        self.pw_ent    = self._add_field("Passphrase mới:", show="*")

        ttk.Button(self, text="Submit", command=self.do_recover).pack(pady=10)
        ttk.Button(self, text="← Back to Login",
                   command=lambda: controller.show_frame(LoginFrame)).pack()

    def _add_field(self, label, show=None):
        ttk.Label(self, text=label).pack(anchor="w", padx=20, pady=2)
        ent = ttk.Entry(self, show=show)
        ent.pack(fill="x", padx=20)
        return ent

    def do_recover(self):
        email = self.email_ent.get().strip()
        code  = self.code_ent.get().strip()
        newpw = self.pw_ent.get().strip()
        if not email or not code or not newpw:
            return messagebox.showerror("Error", "Không được để trống trường nào.")

        # 1) Đầu tiên: recover (decrypt rồi re-encrypt private-key)
        ok_rec, key_path = recover_private_key(email, code, newpw)
        if not ok_rec:
            # nếu code sai hoặc GCM tag mismatch sẽ dừng ở đây
            return messagebox.showerror("Recover Key Failed", key_path)

        # 2) Sau khi private-key đã được xử lý xong, mới reset mật khẩu
        ok_pw, msg_pw = reset_password_with_recovery(email, code, newpw)
        if not ok_pw:
            return messagebox.showerror("Reset PW Failed", msg_pw)

        # 3) Thông báo duy nhất một popup thành công
        messagebox.showinfo(
            "Success",
            f"🎉 Khôi phục thành công!\n"
            f"– Mật khẩu đã được đổi.\n"
        )

        # 4) Quay về Login
        self.ctrl.show_frame(LoginFrame)


class DashboardFrame(ttk.Frame):
    def __init__(self, parent, controller: App):
        super().__init__(parent)
        self.ctrl = controller

        ttk.Label(self, text="🏠 Dashboard", font=("TkDefaultFont", 14)).pack(pady=5)

        # ========== User Sections ==========
        # RSA Keys
        frame_rsa = ttk.LabelFrame(self, text="RSA Key Management")
        frame_rsa.pack(fill="x", padx=10, pady=5)
        for txt, fn in [
            ("Tạo cặp RSA Key", controller.handle_create_rsa if False else None),  # placeholder
        ]:
            pass
        ttk.Button(frame_rsa, text="Tạo cặp RSA Key", command=self.create_key).pack(side="left", padx=5, pady=5)
        ttk.Button(frame_rsa, text="Key Status",       command=self.check_key_status).pack(side="left", padx=5)
        ttk.Button(frame_rsa, text="Renew Key",        command=self.renew_key).pack(side="left", padx=5)
        ttk.Button(frame_rsa, text="Delete Key",       command=self.delete_key).pack(side="left", padx=5)
        ttk.Button(frame_rsa, text="QR Public Key",    command=self.qr_public_key).pack(side="left", padx=5)

        # Crypto
        frame_crypto = ttk.LabelFrame(self, text="Encryption / Decryption")
        frame_crypto.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_crypto, text="Encrypt File", command=self.encrypt_file).pack(side="left", padx=5)
        ttk.Button(frame_crypto, text="Decrypt File", command=self.decrypt_file).pack(side="left", padx=5)

        # Signature
        frame_sig = ttk.LabelFrame(self, text="Signature")
        frame_sig.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_sig, text="Sign File",   command=self.sign_file).pack(side="left", padx=5)
        ttk.Button(frame_sig, text="Verify Sig",  command=self.verify_signature).pack(side="left", padx=5)

        # Account
        frame_acc = ttk.LabelFrame(self, text="Account Management")
        frame_acc.pack(fill="x", padx=10, pady=5)
        ttk.Button(frame_acc, text="View Info",   command=self.view_account).pack(side="left", padx=5)
        ttk.Button(frame_acc, text="Update Info", command=self.update_account).pack(side="left", padx=5)
        ttk.Button(frame_acc, text="Change PW",   command=self.change_pass).pack(side="left", padx=5)
        ttk.Button(frame_acc, text="Delete Acc",  command=self.delete_account).pack(side="left", padx=5)

        # Admin Operations
        self.admin_frame = ttk.LabelFrame(self, text="Admin Operations")

        # Danh sách (label, command)
        ops = [
            ("List Users",    self.admin_list_users),
            ("Lock User",     self.admin_lock),
            ("Unlock User",   self.admin_unlock),
            ("Promote Admin", self.admin_promote),
            ("Demote Admin",  self.admin_demote),
            ("View Logs",     self.admin_view_logs),
            ("User Stats",    self.admin_stats),
        ]

        # Grid: 6 nút hàng 0, nút cuối (User Stats) hàng 1, cột 0
        for idx, (label, cmd) in enumerate(ops):
            if idx < 6:
                row, col = 0, idx
            else:
                row, col = 1, 0

            btn = ttk.Button(self.admin_frame, text=label, command=cmd)
            btn.grid(row=row, column=col, padx=5, pady=4, sticky="ew")
            self.admin_frame.columnconfigure(col, weight=1)

        # Cuối cùng mới pack frame ra
        self.admin_frame.pack(side="top", fill="x", padx=10, pady=5)

        # Logout button
        self.logout_btn = ttk.Button(self, text="🚪 Đăng xuất", command=lambda: controller.show_frame(LoginFrame))
        # dùng side="bottom" để nó luôn dồn xuống cuối Frame
        self.logout_btn.pack(side="bottom", fill="x", pady=10)

    def on_show(self):
        # show/hide admin frame based on role
        if is_admin_or_owner(self.ctrl.current_user):
            self.admin_frame.pack(fill="x", padx=10, pady=5)
        else:
            self.admin_frame.pack_forget()

    # ----- RSA methods -----
    def create_key(self):
            pw = simpledialog.askstring(
                "Passphrase",
                "Nhập passphrase để mã hóa private key:",
                show="*"
            )
            if pw is None:
                return
            pw = pw.strip()
            if not pw:
                return messagebox.showerror("Error", "Passphrase không được để trống.")

            ok, pub_path = create_rsa_keypair(self.ctrl.current_user, pw)
            if ok:
                messagebox.showinfo("Tạo RSA Key", "🎉 Tạo cặp khóa thành công!")
            else:
                messagebox.showerror("Tạo RSA Key thất bại", pub_path)

    def check_key_status(self):
        meta = load_metadata(self.ctrl.current_user)
        if not meta:
            return messagebox.showinfo("Key Status", "Chưa có keypair RSA.")

        # helper: lấy phần date, đảo sang DD/MM/YYYY
        def fmt_date(iso_str):
            date_part = iso_str.split("T")[0]       # "YYYY-MM-DD"
            y, m, d  = date_part.split("-")
            return f"{d}/{m}/{y}"

        created = fmt_date(meta["created_at"])
        expires = fmt_date(meta["expires_at"])
        expired = is_key_expired(self.ctrl.current_user)

        text = (
            f"Đã tạo   : {created}\n"
            f"Hết hạn  : {expires}\n"
            f"Tình trạng: {'Đã hết hạn' if expired else 'Còn hạn'}"
        )
        messagebox.showinfo("Key Status", text)

    def renew_key(self):
            pw = simpledialog.askstring(
                "Passphrase",
                "Nhập passphrase hiện tại:",
                show="*"
            )
            if pw is None:
                return
            pw = pw.strip()
            if not pw:
                return messagebox.showerror("Error", "Passphrase không được để trống.")

            ok, new_pub = renew_key_if_needed(self.ctrl.current_user, pw)
            if ok:
                messagebox.showinfo("Gia hạn Key", "🔄 Gia hạn khóa thành công!")
            else:
                # new_pub lúc này chứa thông báo lỗi, ví dụ "Chưa hết hạn" hoặc lý do khác
                messagebox.showerror("Gia hạn thất bại", new_pub)

    def delete_key(self):
        ok = remove_keypair(self.ctrl.current_user)
        messagebox.showinfo("Delete Key", "Deleted." if ok else "No key found.")

    def qr_public_key(self):
        parent = self.winfo_toplevel()
        popup = tk.Toplevel(parent)
        popup.title("QR Code Options")
        popup.transient(parent)
        popup.grab_set()
        popup.resizable(False, False)

        ttk.Label(popup, text="Bạn muốn làm gì với QR Code?", padding=10).pack()

        ttk.Button(popup, text="Xuất QR Code", width=20,
                   command=lambda: (popup.destroy(), self.qr_export())
                  ).pack(pady=5, padx=20)
        ttk.Button(popup, text="Nhập QR Code", width=20,
                   command=lambda: (popup.destroy(), self.qr_import())
                  ).pack(pady=5, padx=20)

        ttk.Separator(popup).pack(fill="x", pady=5, padx=10)
        ttk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=(0,10))

        popup.protocol("WM_DELETE_WINDOW", popup.destroy)
        popup.wait_window()


    def qr_export(self):
        # 1) hỏi user chỗ lưu
        save_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG Image","*.png")],
            title="Lưu QR Code"
        )
        if not save_path:
            return

        # 2) tạo QR code vào file tạm
        ok, tmp_path = create_qr_code_for_public_key(self.ctrl.current_user)
        if not ok:
            return messagebox.showerror("QR Export", tmp_path)

        # 3) copy file tạm đến nơi user chọn
        try:
            shutil.copy(tmp_path, save_path)
            messagebox.showinfo("QR Export", f"Đã lưu QR Code tại:\n{save_path}")
        except Exception as e:
            messagebox.showerror("QR Export Error", str(e))


    def qr_import(self):
        # 1) hỏi user chọn file QR hiện có
        file_path = filedialog.askopenfilename(
            filetypes=[("PNG Image","*.png"), ("All files","*.*")],
            title="Chọn file QR Code để import"
        )
        if not file_path:
            return

        # 2) đọc và import
        ok, res = read_qr_code_from_file(file_path, self.ctrl.current_user)
        if ok:
            # Chỉ hiện thông báo thành công, không show đường dẫn hay nội dung res
            messagebox.showinfo("QR Import", "✅ Import QR Code thành công!")
        else:
            # Nếu lỗi, show luôn lỗi trả về
            messagebox.showerror("QR Import thất bại", res)

    # ----- Crypto methods -----
    def ask_encrypt_mode(self) -> bool | None:
        """
        Popup hỏi user muốn gộp key hay tách key.
        Trả về True nếu gộp, False nếu tách, None nếu Cancel.
        """
        parent = self.winfo_toplevel()
        popup = tk.Toplevel(parent)
        popup.title("Chọn mode mã hóa")
        popup.transient(parent); popup.grab_set()
        popup.resizable(False, False)

        choice = {"merged": None}
        ttk.Label(popup, text="Bạn muốn gộp session-key vào 1 file?", padding=10).pack()

        btns = ttk.Frame(popup); btns.pack(pady=5)
        ttk.Button(btns, text="Gộp key", width=20,
                   command=lambda: (choice.update(merged=True), popup.destroy())
                  ).pack(pady=2)
        ttk.Button(btns, text="Tách key", width=20,
                   command=lambda: (choice.update(merged=False), popup.destroy())
                  ).pack(pady=2)

        ttk.Separator(popup).pack(fill="x", pady=5, padx=10)
        ttk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=(0,10))
        popup.protocol("WM_DELETE_WINDOW", popup.destroy)
        popup.wait_window()
        return choice["merged"]


    def encrypt_file(self):
        # 1) Chọn file cần mã hóa
        src = filedialog.askopenfilename(title="Chọn file cần mã hóa")
        if not src:
            return

        # 2) Nhập email người nhận
        recv = simpledialog.askstring("Người nhận", "Email người nhận:")
        if not recv:
            return messagebox.showerror("Error", "Bạn phải nhập email người nhận.")

        # 3) Chọn mode gộp/tách
        merged = self.ask_encrypt_mode()
        if merged is None:
            return  # hủy

        # 4) Chọn nơi lưu
        if merged:
            save_path = filedialog.asksaveasfilename(
                defaultextension=".enc",
                filetypes=[("Encrypted file","*.enc")],
                title="Lưu file .enc"
            )
            if not save_path:
                return
        else:
            # chọn thư mục để lưu cả hai file
            save_dir = filedialog.askdirectory(title="Chọn thư mục để lưu các file mã hóa")
            if not save_dir:
                return

        # 5) Thực hiện mã hóa và copy đầu ra
        try:
            res = encrypt_file(src, self.ctrl.current_user, recv, merged=merged)
            if merged:
                # res là đường dẫn file .enc tạm
                shutil.copy(res, save_path)
            else:
                # res là (ct_path, key_path)
                ct_path, key_path = res
                shutil.copy(ct_path, os.path.join(save_dir, os.path.basename(ct_path)))
                shutil.copy(key_path, os.path.join(save_dir, os.path.basename(key_path)))

            messagebox.showinfo("Encrypt", "✅ Mã hóa thành công!")
        except Exception as e:
            messagebox.showerror("Encrypt Error", str(e))


    def ask_decrypt_mode(self) -> bool | None:
        """
        Popup hỏi user file đã gộp key chưa.
        True = merged, False = separate, None = cancel.
        """
        parent = self.winfo_toplevel()
        popup = tk.Toplevel(parent)
        popup.title("Chọn mode giải mã")
        popup.transient(parent); popup.grab_set()
        popup.resizable(False, False)

        choice = {"merged": None}
        ttk.Label(popup, text="File đã gộp session-key chưa?", padding=10).pack()

        btns = ttk.Frame(popup); btns.pack(pady=5)
        ttk.Button(btns, text="Gộp 1 file (.enc)", width=20,
                   command=lambda: (choice.update(merged=True), popup.destroy())
                  ).pack(pady=2)
        ttk.Button(btns, text="Tách 2 file (.enc + .key)", width=20,
                   command=lambda: (choice.update(merged=False), popup.destroy())
                  ).pack(pady=2)

        ttk.Separator(popup).pack(fill="x", pady=5, padx=10)
        ttk.Button(popup, text="Cancel", command=popup.destroy).pack(pady=(0,10))
        popup.protocol("WM_DELETE_WINDOW", popup.destroy)
        popup.wait_window()
        return choice["merged"]

    def decrypt_file(self):
        # 1) hỏi merged / separate
        merged = self.ask_decrypt_mode()
        if merged is None:
            return

        # 2) chọn file .enc
        enc_path = filedialog.askopenfilename(
            title="Chọn file .enc",
            filetypes=[("Encrypted file","*.enc"),("All files","*.*")]
        )
        if not enc_path:
            return

        # 3) nếu separate, chọn thêm .key
        key_path = None
        if not merged:
            key_path = filedialog.askopenfilename(
                title="Chọn file .key",
                filetypes=[("Key file","*.key"),("All files","*.*")]
            )
            if not key_path:
                return

        # 4) nhập passphrase
        pw = simpledialog.askstring(
            "Passphrase",
            "Nhập passphrase private key:",
            show="*"
        )
        if pw is None or not pw.strip():
            return

        # 5) thử decrypt
        try:
            out_path, _meta = decrypt_file(
                enc_path,
                self.ctrl.current_user,
                pw,
                merged=merged,
                key_file_path=key_path
            )
        except Exception as e:
            return messagebox.showerror("Decrypt Error", str(e))

        # 6) nếu decrypt OK, hỏi nơi lưu và copy file
        save_path = filedialog.asksaveasfilename(
            title="Chọn nơi lưu file đã giải mã",
            initialfile=os.path.basename(out_path),
            filetypes=[("All files","*.*")]
        )
        if not save_path:
            return

        try:
            shutil.copy(out_path, save_path)
        except Exception as e:
            return messagebox.showerror("Save Error", str(e))

        messagebox.showinfo("Decrypt", "✅ Giải mã thành công!")

    # ----- Signature methods -----
    def sign_file(self):
        # 1) Chọn file cần ký
        src = filedialog.askopenfilename(
            title="Chọn file cần ký",
            filetypes=[("All files","*.*")]
        )
        if not src:
            return

        # 2) Nhập passphrase để mở private key
        pw = simpledialog.askstring(
            "Passphrase",
            "Nhập passphrase private key:",
            show="*"
        )
        if pw is None or not pw.strip():
            return

        # 3) Ký file, nhận đường dẫn file .sig (cùng thư mục file gốc)
        try:
            sig_path = sign_file(src, self.ctrl.current_user, pw)
        except Exception as e:
            return messagebox.showerror("Sign Error", str(e))

        # 4) Thông báo thành công + hiển thị nơi lưu tự động
        messagebox.showinfo(
            "Sign",
            f"✅ Ký file thành công!\nChữ ký được lưu tại:\n{sig_path}"
        )


    def verify_signature(self):
        # 1) Chọn file gốc
        orig = filedialog.askopenfilename(
            title="Chọn file gốc",
            filetypes=[("All files","*.*")]
        )
        if not orig:
            return

        # 2) Chọn file .sig
        sig = filedialog.askopenfilename(
            title="Chọn file chữ ký (.sig)",
            filetypes=[("Signature file","*.sig"),("All files","*.*")]
        )
        if not sig:
            return

        # 3) Thực hiện xác thực
        try:
            ok, signers = verify_signature(orig, sig)
        except Exception as e:
            return messagebox.showerror("Verify Error", str(e))

        # 4) Hiển thị kết quả
        if ok and signers:
            # chỉ show email, nối bằng dấu phẩy
            emails = ", ".join(signers)
            messagebox.showinfo(
                "Verify",
                f"✅ Xác thực thành công!\nNgười ký: {emails}"
            )
        else:
            messagebox.showerror("Verify", "❌ Xác thực thất bại.")

    # ----- Account methods -----
    def view_account(self):
        info = get_user_info(self.ctrl.current_user)
        if not info:
            return messagebox.showerror("Error", "Không lấy được thông tin tài khoản.")

        # helper format ngày ISO → DD/MM/YYYY
        def fmt_date(iso_str):
            try:
                y, m, d = iso_str.split("T")[0].split("-")
                return f"{d}/{m}/{y}"
            except Exception:
                return iso_str

        # build từng dòng
        lines = [
            f"📧 Email       : {info.get('email','-')}",
            f"👤 Họ và tên   : {info.get('name','-')}",
            f"🎂 Ngày sinh   : {fmt_date(info.get('dob','-'))}",
            f"📱 SĐT         : {info.get('phone','-')}",
            f"🏠 Địa chỉ     : {info.get('address','-')}",
            f"🔑 Vai trò     : {info.get('role','-').capitalize()}"
        ]

        messagebox.showinfo(
            "Thông tin tài khoản",
            "\n".join(lines),
            parent=self
        )

    def update_account(self):
        parent = self.winfo_toplevel()

        # 1) Nhập passphrase
        pw = simpledialog.askstring(
            "Passphrase",
            "Nhập passphrase hiện tại để xác thực:",
            show="*",
            parent=parent
        )
        if pw is None or not pw.strip():
            # Cancel hoặc blank → hủy
            return

        data = {}

        # 2) Hỏi từng field (parent=parent để popup modal)
        name = simpledialog.askstring(
            "Họ và tên",
            "Nhập Họ và tên mới (blank=skip):",
            parent=parent
        )
        if name is not None and name.strip():
            data["name"] = name.strip()

        dob = simpledialog.askstring(
            "Ngày sinh",
            "Nhập Ngày sinh mới (YYYY-MM-DD, blank=skip):",
            parent=parent
        )
        if dob is not None and dob.strip():
            data["dob"] = dob.strip()

        phone = simpledialog.askstring(
            "Số điện thoại",
            "Nhập Số điện thoại mới (blank=skip):",
            parent=parent
        )
        if phone is not None and phone.strip():
            data["phone"] = phone.strip()

        addr = simpledialog.askstring(
            "Địa chỉ",
            "Nhập Địa chỉ mới (blank=skip):",
            parent=parent
        )
        if addr is not None and addr.strip():
            data["address"] = addr.strip()

        # 3) Nếu không thay đổi gì thì báo và dừng
        if not data:
            return messagebox.showinfo(
                "Update Info",
                "⚠️ Bạn chưa thay đổi trường nào.",
                parent=parent
            )

        # 4) Gọi update và show kết quả
        ok, msg = update_user_info(self.ctrl.current_user, pw, data)
        if ok:
            messagebox.showinfo(
                "Update Info",
                "✅ Cập nhật thông tin thành công.",
                parent=parent
            )
        else:
            messagebox.showerror(
                "Update Info",
                f"❌ Cập nhật thất bại:\n{msg}",
                parent=parent
            )

    def change_pass(self):
        parent = self.winfo_toplevel()

        # 1) Nhập passphrase hiện tại
        old_pw = simpledialog.askstring(
            "Xác thực",
            "Nhập passphrase hiện tại:",
            show="*",
            parent=parent
        )
        if old_pw is None:
            return

        # 2) Nhập passphrase mới
        new_pw = simpledialog.askstring(
            "Mật khẩu mới",
            "Nhập passphrase mới:",
            show="*",
            parent=parent
        )
        if new_pw is None or not new_pw.strip():
            return messagebox.showerror(
                "Error",
                "Passphrase mới không được để trống.",
                parent=parent
            )

        # 3) Gọi hàm và bẫy mọi exception
        try:
            ok, msg = change_passphrase(self.ctrl.current_user, old_pw, new_pw)
        except Exception as e:
            return messagebox.showerror(
                "Change PW Error",
                str(e),
                parent=parent
            )

        # 4) Hiển thị kết quả
        if ok:
            messagebox.showinfo(
                "Change PW",
                msg,
                parent=parent
            )
        else:
            messagebox.showerror(
                "Change PW",
                msg,
                parent=parent
            )

    def delete_account(self):
        pw = simpledialog.askstring("Passphrase","Passphrase:", show="*")
        ok, msg = delete_account(self.ctrl.current_user, pw)
        messagebox.showinfo("Delete Acc", msg)
        if ok:
            delete_recovery_code(self.ctrl.current_user)
            delete_recovery_backup(self.ctrl.current_user)
            self.ctrl.show_frame(LoginFrame)

    # ----- Admin methods -----
    def admin_list_users(self):
        ok, data = list_all_users(self.ctrl.current_user)
        if not ok:
            return messagebox.showerror("Admin Error", data)
        win = tk.Toplevel(self)
        win.title("User List")
        txt = tk.Text(win, width=60, height=20); txt.pack()
        for u in data:
            txt.insert("end", f"{u['email']:30}{u['role']:8}{u['locked']}\n")

    def admin_lock(self):
        # 1) Nhập email target
        tgt = simpledialog.askstring("Lock User", "Email target:")
        if not tgt:
            return

        # 2) Xác nhận hành động
        if not messagebox.askyesno(
            "Xác nhận khóa",
            f"Bạn có chắc muốn khóa tài khoản '{tgt}'?"
        ):
            return

        # 3) Nhập mật khẩu admin
        pw = simpledialog.askstring(
            "Admin Password",
            "Nhập mật khẩu admin để xác thực:",
            show="*"
        )
        if pw is None:
            return

        # 4) Thực hiện và show kết quả
        ok, msg = lock_user_account(self.ctrl.current_user, tgt, pw)
        messagebox.showinfo("Lock User", msg)


    def admin_unlock(self):
        tgt = simpledialog.askstring("Unlock User", "Email target:")
        if not tgt:
            return

        if not messagebox.askyesno(
            "Xác nhận mở khóa",
            f"Bạn có chắc muốn mở khóa tài khoản '{tgt}'?"
        ):
            return

        pw = simpledialog.askstring(
            "Admin Password",
            "Nhập mật khẩu admin để xác thực:",
            show="*"
        )
        if pw is None:
            return

        ok, msg = unlock_user_account(self.ctrl.current_user, tgt, pw)
        messagebox.showinfo("Unlock User", msg)


    def admin_promote(self):
        tgt = simpledialog.askstring("Promote to Admin", "Email target:")
        if not tgt:
            return

        if not messagebox.askyesno(
            "Xác nhận thăng quyền",
            f"Bạn có chắc muốn thăng '{tgt}' thành admin?"
        ):
            return

        pw = simpledialog.askstring(
            "Admin Password",
            "Nhập mật khẩu admin để xác thực:",
            show="*"
        )
        if pw is None:
            return

        ok, msg = promote_to_admin(self.ctrl.current_user, tgt, pw)
        messagebox.showinfo("Promote to Admin", msg)


    def admin_demote(self):
        tgt = simpledialog.askstring("Demote from Admin", "Email target:")
        if not tgt:
            return

        if not messagebox.askyesno(
            "Xác nhận hạ quyền",
            f"Bạn có chắc muốn hạ quyền admin của '{tgt}'?"
        ):
            return

        pw = simpledialog.askstring(
            "Admin Password",
            "Nhập mật khẩu admin để xác thực:",
            show="*"
        )
        if pw is None:
            return

        ok, msg = demote_from_admin(self.ctrl.current_user, tgt, pw)
        messagebox.showinfo("Demote from Admin", msg)

    def admin_view_logs(self):
        pw = simpledialog.askstring("Pass","Admin pass:", show="*")
        ok, logs = view_system_logs(self.ctrl.current_user, pw)
        if not ok:
            return messagebox.showerror("Error", logs)
        win = tk.Toplevel(self); win.title("Logs")
        txt = tk.Text(win, width=80, height=30); txt.pack()
        for e in logs:
            txt.insert("end", f"{e['timestamp']} | {e['email']} | {e['action']} | {e['status']}\n")

    def admin_stats(self):
        ok, stats = get_user_statistics(self.ctrl.current_user)
        if not ok:
            return messagebox.showerror("Error", stats)
        messagebox.showinfo("Stats", "\n".join(f"{k}: {v}" for k,v in stats.items()))


if __name__ == "__main__":
    App().mainloop()