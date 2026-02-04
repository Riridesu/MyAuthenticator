#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
現代化 UI 安全驗證器 (v1.3.2 - Optimized Stable)
- 優化：Base32 清理、進度條一致、解密容錯、UI 穩定性
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import pyotp
import time
import json
import os
import pyperclip
import base64
import urllib.parse
import tempfile
from pathlib import Path
import logging
import ctypes
import sys
import traceback
from cryptography.fernet import Fernet

# --------------------------
# 0. 系統環境設定
# --------------------------
APP_NAME = "ModernAuthenticator"
SCALE_FACTOR = 1.0

try:
    if os.name == 'nt':
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        HDC = ctypes.windll.user32.GetDC(0)
        SYSTEM_DPI = ctypes.windll.gdi32.GetDeviceCaps(HDC, 88)
        ctypes.windll.user32.ReleaseDC(0, HDC)
        SCALE_FACTOR = SYSTEM_DPI / 96.0
except Exception:
    SCALE_FACTOR = 1.0

def S(size: int) -> int:
    return int(size * SCALE_FACTOR)

if os.name == 'nt':
    BASE_DIR = Path(os.getenv('LOCALAPPDATA') or Path.home()) / APP_NAME
else:
    BASE_DIR = Path.home() / f".{APP_NAME}"

BASE_DIR.mkdir(parents=True, exist_ok=True)
DATA_FILE = BASE_DIR / "tokens.encrypted"
KEY_FILE = BASE_DIR / "secret.key"
LOG_FILE = BASE_DIR / "error.log"

logging.basicConfig(filename=LOG_FILE, level=logging.ERROR,
                    format='%(asctime)s %(message)s')

# --------------------------
# 1. 安全性模組 (DPAPI + Fernet)
# --------------------------
try:
    import win32crypt
    _HAS_DPAPI = True
except ImportError:
    _HAS_DPAPI = False

class SecurityManager:
    @staticmethod
    def load_key() -> bytes:
        if KEY_FILE.exists():
            try:
                raw = KEY_FILE.read_bytes()
                if _HAS_DPAPI and os.name == 'nt':
                    try:
                        dec = win32crypt.CryptUnprotectData(raw, None, None, None, 0)
                        return dec[1]
                    except Exception:
                        logging.error("DPAPI Decrypt failed. Key might be from another PC.")
                        pass
                return raw
            except Exception as e:
                logging.error(f"Key load error: {e}")
        return SecurityManager.reset_key()

    @staticmethod
    def reset_key() -> bytes:
        if KEY_FILE.exists():
            try:
                os.rename(KEY_FILE, f"{KEY_FILE}.bak.{int(time.time())}")
            except Exception:
                pass
        key = Fernet.generate_key()
        SecurityManager.save_key(key)
        return key

    @staticmethod
    def save_key(key: bytes):
        try:
            data_to_write = key
            if _HAS_DPAPI and os.name == 'nt':
                prot = win32crypt.CryptProtectData(key, None, None, None, None, 0)
                data_to_write = prot[0] if isinstance(prot, tuple) else bytes(prot)
            KEY_FILE.write_bytes(data_to_write)
        except Exception as e:
            logging.error(f"Key save error: {e}")
            try:
                KEY_FILE.write_bytes(key)
            except Exception:
                pass

    @staticmethod
    def decrypt_data() -> list:
        if not DATA_FILE.exists():
            return []
        try:
            key = SecurityManager.load_key()
            f = Fernet(key)
            decrypted = f.decrypt(DATA_FILE.read_bytes())
            data = json.loads(decrypted.decode("utf-8"))
            return data if isinstance(data, list) else []
        except Exception as e:
            logging.error(f"Data decrypt error: {e}")
            return []

    @staticmethod
    def save_data(data: list):
        try:
            key = SecurityManager.load_key()
            f = Fernet(key)
            encrypted = f.encrypt(json.dumps(data, ensure_ascii=False).encode("utf-8"))

            with tempfile.NamedTemporaryFile(delete=False, dir=BASE_DIR) as tf:
                tf.write(encrypted)
                tmp_name = tf.name

            os.replace(tmp_name, str(DATA_FILE))
        except Exception as e:
            logging.error(f"Save data error: {e}")
            try:
                messagebox.showerror("存檔失敗", f"無法寫入資料: {e}")
            except Exception:
                pass

# --------------------------
# 2. Google Migration 解碼器
# --------------------------
class GoogleMigrationDecoder:
    @staticmethod
    def decode(url: str) -> list:
        try:
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            if 'data' not in params:
                return []

            data_b64 = params['data'][0]
            payload = base64.urlsafe_b64decode(data_b64 + '=' * (-len(data_b64) % 4))
            return GoogleMigrationDecoder._parse_payload(payload)
        except Exception:
            return []

    @staticmethod
    def _parse_payload(data):
        accounts = []
        idx = 0
        while idx < len(data):
            tag = data[idx]
            idx += 1
            field_num = tag >> 3
            wire_type = tag & 0x07

            if field_num == 1 and wire_type == 2:
                length, idx = GoogleMigrationDecoder._read_varint(data, idx)
                sub_data = data[idx : idx + length]
                idx += length
                acc = GoogleMigrationDecoder._parse_account(sub_data)
                if acc:
                    accounts.append(acc)
            elif wire_type == 2:
                length, idx = GoogleMigrationDecoder._read_varint(data, idx)
                idx += length
            elif wire_type == 0:
                _, idx = GoogleMigrationDecoder._read_varint(data, idx)
            else:
                break
        return accounts

    @staticmethod
    def _read_varint(data, idx):
        result = 0
        shift = 0
        while True:
            if idx >= len(data):
                return result, idx
            byte = data[idx]
            idx += 1
            result |= (byte & 0x7F) << shift
            if not (byte & 0x80):
                return result, idx
            shift += 7

    @staticmethod
    def _parse_account(data):
        secret = b""
        name = ""
        issuer = ""
        idx = 0
        while idx < len(data):
            tag = data[idx]
            idx += 1
            field_num = tag >> 3
            wire_type = tag & 0x07

            if wire_type == 2:
                length, idx = GoogleMigrationDecoder._read_varint(data, idx)
                val = data[idx : idx + length]
                idx += length
                if field_num == 1:
                    secret = val
                elif field_num == 2:
                    name = val.decode('utf-8', 'ignore')
                elif field_num == 3:
                    issuer = val.decode('utf-8', 'ignore')
            elif wire_type == 0:
                _, idx = GoogleMigrationDecoder._read_varint(data, idx)

        if secret:
            try:
                secret_b32 = base64.b32encode(secret).decode().replace("=", "")
                disp_name = f"{issuer} ({name})" if issuer else name
                return {"name": disp_name, "secret": secret_b32}
            except Exception:
                pass
        return None

# --------------------------
# 3. UI 元件
# --------------------------
COLOR_BG = "#121212"
COLOR_CARD = "#1E1E1E"
COLOR_TEXT = "#E0E0E0"
COLOR_ACCENT = "#BB86FC"
COLOR_DANGER = "#CF6679"
COLOR_SUCCESS = "#03DAC6"

class DarkInputDialog(tk.Toplevel):
    def __init__(self, parent, title, prompt):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.geometry(f"{S(400)}x{S(180)}")
        self.configure(bg=COLOR_BG)
        self.resizable(False, False)

        try:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - S(200)
            y = parent.winfo_y() + (parent.winfo_height() // 2) - S(90)
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

        tk.Label(self, text=prompt, bg=COLOR_BG, fg=COLOR_TEXT, font=("Arial", 11)).pack(pady=S(15))

        self.entry = tk.Entry(self, bg="#2C2C2C", fg="white", insertbackground="white", relief="flat", font=("Arial", 11))
        self.entry.pack(fill="x", padx=S(20), ipady=S(4))
        self.entry.focus_set()

        btn_frame = tk.Frame(self, bg=COLOR_BG)
        btn_frame.pack(side="bottom", pady=S(15))

        tk.Button(btn_frame, text="確定", command=self.on_ok, bg=COLOR_ACCENT, fg="black", width=8, relief="flat").pack(side="left", padx=5)
        tk.Button(btn_frame, text="取消", command=self.destroy, bg="#333", fg="white", width=8, relief="flat").pack(side="left", padx=5)

        self.bind('<Return>', lambda e: self.on_ok())
        self.bind('<Escape>', lambda e: self.destroy())
        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def on_ok(self):
        self.result = self.entry.get()
        self.destroy()

# --------------------------
# 4. 主程式 App
# --------------------------
class AuthenticatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Authenticator")
        self.root.geometry(f"{S(420)}x{S(700)}")
        self.root.configure(bg=COLOR_BG)

        self.accounts = SecurityManager.decrypt_data()

        header = tk.Frame(root, bg=COLOR_BG, height=S(60))
        header.pack(fill="x", padx=S(15), pady=S(10))

        tk.Label(header, text="Authenticator", font=("Arial", 18, "bold"), bg=COLOR_BG, fg=COLOR_TEXT).pack(side="left")

        btn_bar = tk.Frame(header, bg=COLOR_BG)
        btn_bar.pack(side="right")

        self.make_btn(btn_bar, "＋", COLOR_ACCENT, self.add_account)
        self.make_btn(btn_bar, "📥", COLOR_SUCCESS, self.import_google)
        self.make_btn(btn_bar, "📤", "#FFA500", self.export_backup)
        self.make_btn(btn_bar, "↻", COLOR_DANGER, self.factory_reset)

        container = tk.Frame(root, bg=COLOR_BG)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg=COLOR_BG, highlightthickness=0)
        self.scrollbar = ttk.Scrollbar(container, orient="vertical", command=self.canvas.yview)
        self.scroll_frame = tk.Frame(self.canvas, bg=COLOR_BG)

        self.window_id = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")

        self.scroll_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.window_id, width=e.width))
        self.canvas.configure(yscrollcommand=self.scrollbar.set)

        self.canvas.pack(side="left", fill="both", expand=True)
        self.scrollbar.pack(side="right", fill="y")

        self.root.bind_all("<MouseWheel>", self._on_mousewheel)

        self.refresh_list()
        self.update_loop()

    def make_btn(self, parent, text, color, cmd):
        lbl = tk.Label(parent, text=text, fg=color, bg=COLOR_BG, font=("Arial", 14, "bold"), cursor="hand2", padx=6)
        lbl.pack(side="left")
        lbl.bind("<Button-1>", lambda e: cmd())
        return lbl

    def _on_mousewheel(self, event):
        self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")

    def refresh_list(self):
        for widget in self.scroll_frame.winfo_children():
            widget.destroy()

        self.code_labels = []

        if not self.accounts:
            tk.Label(self.scroll_frame, text="\n\n尚無帳戶\n\n點擊 ＋ 新增帳戶\n點擊 📥 匯入連結\n點擊 📤 備份資料",
                     bg=COLOR_BG, fg="#666", font=("Arial", 12)).pack(fill="x")
            return

        for idx, acc in enumerate(self.accounts):
            self.draw_card(idx, acc)

    def draw_card(self, idx, acc):
        card = tk.Frame(self.scroll_frame, bg=COLOR_CARD, pady=S(10), padx=S(15))
        card.pack(fill="x", padx=S(10), pady=S(5))

        row1 = tk.Frame(card, bg=COLOR_CARD)
        row1.pack(fill="x")
        tk.Label(row1, text=acc.get("name", "Unknown"), font=("Arial", 11, "bold"), fg=COLOR_TEXT, bg=COLOR_CARD).pack(side="left")

        del_btn = tk.Label(row1, text="✕", fg="#555", bg=COLOR_CARD, cursor="hand2", font=("Arial", 10))
        del_btn.pack(side="right")
        del_btn.bind("<Enter>", lambda e: del_btn.config(fg=COLOR_DANGER))
        del_btn.bind("<Leave>", lambda e: del_btn.config(fg="#555"))
        del_btn.bind("<Button-1>", lambda e: self.delete_account(idx))

        row2 = tk.Frame(card, bg=COLOR_CARD)
        row2.pack(fill="x", pady=S(5))

        code_lbl = tk.Label(row2, text="--- ---", font=("Consolas", 22, "bold"), fg=COLOR_ACCENT, bg=COLOR_CARD, cursor="hand2")
        code_lbl.pack(side="left")

        msg_lbl = tk.Label(row2, text="", font=("Arial", 9, "bold"), fg=COLOR_SUCCESS, bg=COLOR_CARD)
        msg_lbl.pack(side="left", padx=10)

        code_lbl.bind("<Button-1>", lambda e, s=acc["secret"]: self.copy_code(s, msg_lbl))

        prog = ttk.Progressbar(card, length=100, mode='determinate')
        prog.pack(fill="x", pady=(S(5), 0))

        self.code_labels.append({"secret": acc["secret"], "label": code_lbl, "progress": prog})

    def copy_code(self, secret, lbl):
        try:
            code = pyotp.TOTP(secret).now()
            pyperclip.copy(code)
            lbl.config(text="✓ Copied!")
            self.root.after(1500, lambda: lbl.config(text=""))
        except Exception:
            pass

    def update_loop(self):
        if not self.root.winfo_exists():
            return
        now = time.time()
        rem = 30 - (now % 30)
        pct = (rem / 30) * 100

        for item in self.code_labels:
            try:
                totp = pyotp.TOTP(item["secret"])
                code = totp.now()
                display = f"{code[:3]} {code[3:]}"
                color = COLOR_DANGER if rem < 5 else COLOR_ACCENT
                item["label"].config(text=display, fg=color)
                item["progress"]["value"] = pct
            except Exception:
                item["label"].config(text="Error")

        self.root.after(500, self.update_loop)

    def add_account(self):
        d_name = DarkInputDialog(self.root, "新增帳戶", "輸入服務名稱:")
        if not d_name.result:
            return
        d_key = DarkInputDialog(self.root, "新增帳戶", "輸入金鑰 (Base32):")
        if not d_key.result:
            return

        try:
            clean_key = d_key.result.replace(" ", "").upper()
            pyotp.TOTP(clean_key).now()
            self.accounts.append({"name": d_name.result, "secret": clean_key})
            SecurityManager.save_data(self.accounts)
            self.refresh_list()
        except Exception:
            messagebox.showerror("錯誤", "無效的金鑰格式")

    def import_google(self):
        d_url = DarkInputDialog(self.root, "匯入", "貼上 otpauth-migration:// 連結:")
        if not d_url.result:
            return

        new_accs = GoogleMigrationDecoder.decode(d_url.result)
        if new_accs:
            count = 0
            exist = {a["secret"] for a in self.accounts}
            for acc in new_accs:
                if acc["secret"] not in exist:
                    self.accounts.append(acc)
                    count += 1
            SecurityManager.save_data(self.accounts)
            self.refresh_list()
            messagebox.showinfo("成功", f"已匯入 {count} 個帳戶")
        else:
            messagebox.showerror("失敗", "無法解析連結或連結無效")

    def export_backup(self):
        if not self.accounts:
            messagebox.showinfo("提示", "沒有資料可供匯出")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
            title="匯出備份 (請妥善保管此檔案)"
        )
        if path:
            try:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self.accounts, f, ensure_ascii=False, indent=2)
                messagebox.showinfo("成功", "備份已匯出。\n\n請注意：此檔案包含明文金鑰，請勿外流。")
            except Exception as e:
                messagebox.showerror("失敗", f"匯出錯誤: {e}")

    def delete_account(self, idx):
        if messagebox.askyesno("確認", "確定要刪除此帳戶嗎？"):
            del self.accounts[idx]
            SecurityManager.save_data(self.accounts)
            self.refresh_list()

    def factory_reset(self):
        if messagebox.askyesno("危險", "這將刪除所有資料！\n\n若您要換電腦，請先使用「📤 匯出」功能。"):
            try:
                if DATA_FILE.exists():
                    os.remove(DATA_FILE)
                if KEY_FILE.exists():
                    os.remove(KEY_FILE)
                self.accounts = []
                self.refresh_list()
            except Exception:
                pass

if __name__ == "__main__":
    try:
        root = tk.Tk()
        app = AuthenticatorApp(root)
        root.mainloop()
    except Exception as e:
        error_msg = traceback.format_exc()
        try:
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(f"\n{time.ctime()}: CRITICAL ERROR\n{error_msg}\n")
            messagebox.showerror("程式崩潰", f"發生未預期的錯誤，已記錄至 Log:\n{e}")
        except Exception:
            print(f"Critical: {e}")