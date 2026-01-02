#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
現代化 UI 安全驗證器 (v1.2.3 - Icon Update)
- UI 優化：將重置圖示更改為「↻」
- 核心功能：智慧遷移 (自動讀取同目錄下的舊版資料)、AppData 安全儲存、一鍵貼上
"""
from __future__ import annotations
import tkinter as tk
from tkinter import ttk
import tkinter.messagebox as messagebox
import pyotp
import time
import json
import os
import shutil
import pyperclip
import base64
import urllib.parse
import asyncio
import tempfile
import argparse
import stat
from pathlib import Path
from typing import List, Dict, Any, Tuple
import logging
import ctypes
import signal
import sys

from cryptography.fernet import Fernet

# --------------------------
# 0. 系統顯示與路徑設定
# --------------------------
SCALE_FACTOR = 1.0

try:
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
    HDC = ctypes.windll.user32.GetDC(0)
    SYSTEM_DPI = ctypes.windll.gdi32.GetDeviceCaps(HDC, 88)
    ctypes.windll.user32.ReleaseDC(0, HDC)
    SCALE_FACTOR = SYSTEM_DPI / 96.0
except Exception:
    SCALE_FACTOR = 1.0

def S(size: int) -> int:
    return int(size * SCALE_FACTOR)

# --- 設定安全的資料儲存目錄 ---
APP_NAME = "ModernAuthenticator"
if os.name == 'nt':
    BASE_DIR = Path(os.getenv('LOCALAPPDATA')) / APP_NAME
else:
    BASE_DIR = Path.home() / f".{APP_NAME}"

BASE_DIR.mkdir(parents=True, exist_ok=True)

LOG_FILE = BASE_DIR / "auth.log"
DATA_FILE = BASE_DIR / "tokens.encrypted"
KEY_FILE = BASE_DIR / "secret.key"

# --------------------------
# 配置與日誌
# --------------------------
logger = logging.getLogger("authenticator")
logger.setLevel(logging.DEBUG)
if logger.handlers:
    logger.handlers.clear()

fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s: %(message)s"))
logger.addHandler(fh)

try:
    from winsdk.windows.security.credentials.ui import UserConsentVerifier
    _HAS_WINSKD = True
except Exception:
    UserConsentVerifier = None
    _HAS_WINSKD = False

try:
    import win32crypt
    _HAS_PYWIN32 = True
except Exception:
    win32crypt = None
    _HAS_PYWIN32 = False

# --------------------------
# UI 風格設定
# --------------------------
COLOR_BG = "#050505"
COLOR_CARD_BG = "#141414"
COLOR_CARD_BORDER = "#333333"
COLOR_PRIMARY = "#4CC9F0"
COLOR_PRIMARY_HOVER = "#80DFFF"

# 重置按鈕顏色 (警告紅)
COLOR_DANGER = "#FF6B6B"       
COLOR_DANGER_HOVER = "#FF8888" 

COLOR_SUCCESS = "#00FF99"
COLOR_TEXT_MAIN = "#FFFFFF"
COLOR_TEXT_SUB = "#AAAAAA"
COLOR_INPUT_BG = "#222222"

FONT_FAMILY = "Microsoft YaHei UI" if os.name == 'nt' else "Arial"
FONT_MAIN = (FONT_FAMILY, 10)
FONT_BOLD = (FONT_FAMILY, 10, "bold")
FONT_TITLE = (FONT_FAMILY, 18, "bold")
FONT_CODE = ("Consolas", 24, "bold")

# --------------------------
# 1. 智慧資料遷移模組 (Smart Migration)
# --------------------------
def migrate_legacy_files():
    """
    智慧偵測舊資料：
    1. 鎖定 .exe 所在的資料夾 (比 cwd 更準確)
    2. 如果發現舊資料，自動搬移到 AppData 安全目錄
    """
    # 判斷程式執行位置 (打包後與未打包的路徑不同)
    if getattr(sys, 'frozen', False):
        # 打包後 (.exe) 的所在目錄
        app_dir = Path(sys.executable).parent
    else:
        # 開發時 (.py) 的所在目錄
        app_dir = Path(__file__).parent

    logger.info(f"Checking for legacy files in: {app_dir}")

    legacy_files = {
        "secret.key": KEY_FILE,
        "tokens.encrypted": DATA_FILE,
        "auth.log": LOG_FILE
    }
    
    migrated_count = 0
    for filename, target_path in legacy_files.items():
        source_path = app_dir / filename
        
        # 邏輯：如果舊位置有檔案，且新位置(AppData)沒有 -> 搬移 (升級)
        if source_path.exists() and not target_path.exists():
            try:
                shutil.move(str(source_path), str(target_path))
                logger.info(f"✅ Migrated {filename} to AppData")
                migrated_count += 1
            except Exception as e:
                logger.error(f"❌ Failed to migrate {filename}: {e}")
        
        # 邏輯：如果舊位置有，新位置也有 -> 視為殘留，為了安全，不覆蓋新資料，但紀錄 Log
        elif source_path.exists() and target_path.exists():
            logger.warning(f"ℹ️ File collision: {filename} exists in both. Using AppData version.")

    if migrated_count > 0:
        logger.info(f"Migration complete. {migrated_count} files moved.")

# --------------------------
# 2. 安全性模組
# --------------------------
class SecurityManager:
    @staticmethod
    def _restrict_file_permissions(path: Path):
        try:
            os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        except Exception:
            pass

    @staticmethod
    def _try_crypt_unprotect(data: bytes) -> bytes:
        if not _HAS_PYWIN32 or not data:
            raise RuntimeError("pywin32 missing")
        try:
            dec = win32crypt.CryptUnprotectData(data, None, None, None, None, 0)
            return dec[1] if isinstance(dec, tuple) else bytes(dec)
        except Exception:
            try:
                dec = win32crypt.CryptUnprotectData(data, None, None, None, 0)
                return dec[1] if isinstance(dec, tuple) else bytes(dec)
            except Exception as e:
                logger.exception("DPAPI Decryption Failed")
                raise e

    @staticmethod
    def _try_crypt_protect(data: bytes) -> bytes:
        if not _HAS_PYWIN32 or not data:
            raise RuntimeError("pywin32 missing")
        try:
            prot = win32crypt.CryptProtectData(data, None, None, None, None, 0)
            if isinstance(prot, tuple):
                return bytes(prot[0])
            return bytes(prot)
        except Exception:
            logger.exception("DPAPI Encryption Failed")
            raise

    @staticmethod
    def load_key() -> bytes:
        try:
            if KEY_FILE.exists():
                raw = KEY_FILE.read_bytes()
                if _HAS_PYWIN32 and os.name == "nt":
                    try:
                        key = SecurityManager._try_crypt_unprotect(raw)
                        return key
                    except Exception as e:
                        logger.error(f"Failed to decrypt key: {e}")
                        SecurityManager._backup_and_reset_keys()
                        return SecurityManager.load_key()
                return raw
            else:
                return SecurityManager._generate_and_save_new_key()
        except Exception:
            logger.exception("Critical Key Loading Error")
            raise

    @staticmethod
    def _backup_and_reset_keys():
        timestamp = int(time.time())
        try:
            if KEY_FILE.exists():
                os.rename(KEY_FILE, f"{KEY_FILE}.bak.{timestamp}")
            if DATA_FILE.exists():
                os.rename(DATA_FILE, f"{DATA_FILE}.bak.{timestamp}")
        except Exception:
            pass

    @staticmethod
    def _generate_and_save_new_key() -> bytes:
        key = Fernet.generate_key()
        if _HAS_PYWIN32 and os.name == "nt":
            protected_key = SecurityManager._try_crypt_protect(key)
            KEY_FILE.write_bytes(protected_key)
        else:
            KEY_FILE.write_bytes(key)
        SecurityManager._restrict_file_permissions(KEY_FILE)
        return key

    @staticmethod
    def encrypt_data(data_list: List[Dict[str, Any]]) -> bytes:
        f = Fernet(SecurityManager.load_key())
        return f.encrypt(json.dumps(data_list, ensure_ascii=False).encode("utf-8"))

    @staticmethod
    def decrypt_data() -> List[Dict[str, Any]]:
        if not DATA_FILE.exists(): return []
        try:
            f = Fernet(SecurityManager.load_key())
            with DATA_FILE.open("rb") as file:
                encrypted_data = file.read()
            decrypted = f.decrypt(encrypted_data)
            obj = json.loads(decrypted.decode("utf-8"))
            return obj["accounts"] if isinstance(obj, dict) else obj
        except Exception:
            return []

    @staticmethod
    def save_data_atomic(data_list: List[Dict[str, Any]]):
        try:
            encrypted = SecurityManager.encrypt_data(data_list)
            with tempfile.NamedTemporaryFile(delete=False, dir=BASE_DIR) as tf:
                tf.write(encrypted)
                tmpname = tf.name
            SecurityManager._restrict_file_permissions(Path(tmpname))
            if DATA_FILE.exists():
                os.replace(tmpname, str(DATA_FILE))
            else:
                os.rename(tmpname, str(DATA_FILE))
            SecurityManager._restrict_file_permissions(DATA_FILE)
        except Exception:
            logger.exception("Save Data Error")
            raise

    @staticmethod
    async def verify_user(force_no_windows_hello: bool = False) -> Tuple[bool, str]:
        if force_no_windows_hello: return True, "Skipped"
        if not _HAS_WINSKD or UserConsentVerifier is None: return True, "No SDK"
        try:
            avail = await UserConsentVerifier.check_availability_async()
            if getattr(avail, "value", 0) == 0:
                res = await UserConsentVerifier.request_verification_async("身分驗證")
                return (True, "Verified") if getattr(res, "value", 1) == 0 else (False, "Failed")
            return True, "Not Configured"
        except Exception as e: return False, str(e)

# --------------------------
# 3. UI 元件
# --------------------------
class ModernButton(tk.Label):
    def __init__(self, parent, text, command, hover_color=COLOR_CARD_BORDER, fg=COLOR_PRIMARY, font=FONT_BOLD, **kwargs):
        super().__init__(parent, text=text, bg=COLOR_BG, fg=fg, font=font, cursor="hand2",
                         padx=S(8), pady=S(4), **kwargs)
        self.command = command
        self.default_bg = COLOR_BG
        self.hover_color = hover_color
        self.default_fg = fg
        self.configure(relief="flat", bd=0)
        self.bind("<Button-1>", lambda e: self._on_click(e))
        self.bind("<Enter>", self.on_enter)
        self.bind("<Leave>", self.on_leave)

    def _on_click(self, e):
        if callable(self.command): self.command()

    def on_enter(self, e):
        self.config(bg=self.hover_color)
        if self.default_fg == COLOR_PRIMARY:
             self.config(fg=COLOR_PRIMARY_HOVER)
        elif self.default_fg == COLOR_DANGER:
             self.config(fg=COLOR_DANGER_HOVER)
        elif self.default_fg == COLOR_TEXT_SUB:
             self.config(fg="white")

    def on_leave(self, e):
        self.config(bg=self.default_bg, fg=self.default_fg)

class NativeDarkDialog(tk.Toplevel):
    def __init__(self, parent, title, message, mode="info", input_mode=False, default_value=""):
        super().__init__(parent)
        self.result = None
        self.title(title)
        self.resizable(True, True)

        base_w = 480
        base_h = 280 if input_mode else 200
        w, h = S(base_w), S(base_h)

        try:
            x = parent.winfo_rootx() + (parent.winfo_width() // 2) - (w // 2)
            y = parent.winfo_rooty() + (parent.winfo_height() // 2) - (h // 2)
            self.geometry(f"{w}x{h}+{x}+{y}")
        except:
            self.geometry(f"{w}x{h}")

        self.configure(bg=COLOR_BG)

        content = tk.Frame(self, bg=COLOR_BG, padx=S(20), pady=S(20))
        content.pack(fill="both", expand=True)

        tk.Label(content, text=message, font=FONT_MAIN, bg=COLOR_BG, fg=COLOR_TEXT_MAIN,
                 wraplength=S(420), justify="left").pack(anchor="w", pady=(0, S(10)))

        self.entry = None
        if input_mode:
            entry_frame = tk.Frame(content, bg=COLOR_BG)
            entry_frame.pack(fill="x")

            self.entry = tk.Entry(entry_frame, font=FONT_MAIN, bg=COLOR_INPUT_BG, fg="white", insertbackground="white", relief="flat")
            self.entry.pack(side="left", fill="x", expand=True, ipady=S(4))
            self.entry.insert(0, default_value)

            paste_btn = tk.Label(entry_frame, text="📋 貼上", font=FONT_BOLD,
                                 bg=COLOR_CARD_BORDER, fg=COLOR_TEXT_MAIN, padx=S(8), pady=S(4), cursor="hand2")
            paste_btn.pack(side="right", padx=(S(8), 0))
            paste_btn.bind("<Button-1>", self._paste_from_clipboard)
            paste_btn.bind("<Enter>", lambda e: paste_btn.config(bg=COLOR_PRIMARY, fg="black"))
            paste_btn.bind("<Leave>", lambda e: paste_btn.config(bg=COLOR_CARD_BORDER, fg=COLOR_TEXT_MAIN))

            self.entry.bind("<Return>", lambda e: self.ok())
            self.entry.bind("<Escape>", lambda e: self.cancel())
            self.entry.focus_force()

        btn_frame = tk.Frame(self, bg=COLOR_BG, pady=S(15), padx=S(15))
        btn_frame.pack(fill="x", side="bottom")

        if mode == "confirm":
            ModernButton(btn_frame, "確認", self.ok, fg=COLOR_DANGER, hover_color="#331111").pack(side="right", padx=5)
            ModernButton(btn_frame, "取消", self.cancel, fg=COLOR_TEXT_SUB).pack(side="right")
        else:
            confirm_fg = COLOR_PRIMARY if not input_mode else COLOR_SUCCESS
            ModernButton(btn_frame, "確定", self.ok, fg=confirm_fg, hover_color="#113322").pack(side="right", padx=5)
            if input_mode:
                ModernButton(btn_frame, "取消", self.cancel, fg=COLOR_TEXT_SUB).pack(side="right")

        self.transient(parent)
        self.grab_set()
        parent.wait_window(self)

    def _paste_from_clipboard(self, event):
        try:
            text = pyperclip.paste()
            if text and self.entry:
                self.entry.delete(0, tk.END)
                self.entry.insert(0, text)
                self.entry.focus_set()
        except Exception:
            pass

    def ok(self):
        if self.entry:
            self.result = self.entry.get()
        else:
            self.result = True
        self.destroy()

    def cancel(self):
        self.result = None
        self.destroy()

# 輔助函式
def ask_string_dark(parent, title, prompt):
    d = NativeDarkDialog(parent, title, prompt, mode="input", input_mode=True)
    return d.result

def show_message_dark(parent, title, message, is_error=False):
    d = NativeDarkDialog(parent, title, message, mode="info")

def ask_confirm_dark(parent, title, message):
    d = NativeDarkDialog(parent, title, message, mode="confirm")
    return d.result is True

class GoogleMigrationDecoder:
    @staticmethod
    def decode(migration_url: str) -> List[Dict[str, str]]:
        parsed = urllib.parse.urlparse(migration_url)
        params = urllib.parse.parse_qs(parsed.query)
        if 'data' not in params: raise ValueError("無效連結")
        data_b64 = params['data'][0]
        payload = base64.urlsafe_b64decode(data_b64 + '=' * (-len(data_b64) % 4))
        accounts = []
        idx = 0
        length = len(payload)
        while idx < length:
            tag = payload[idx]; idx += 1
            field = tag >> 3; wire = tag & 0x07
            if field == 1 and wire == 2:
                l, idx = GoogleMigrationDecoder._varint(payload, idx)
                accounts.append(GoogleMigrationDecoder._parse(payload[idx:idx+l]))
                idx += l
            elif wire == 2: l, idx = GoogleMigrationDecoder._varint(payload, idx); idx += l
            elif wire == 0: _, idx = GoogleMigrationDecoder._varint(payload, idx)
            else: break
        return accounts

    @staticmethod
    def _varint(d, i):
        r = 0; s = 0
        while True:
            if i >= len(d): return None, i
            b = d[i]; i += 1
            r |= (b & 0x7F) << s
            if not (b & 0x80): return r, i
            s += 7

    @staticmethod
    def _parse(d):
        i = 0; l = len(d); s = b""; n = ""; iss = ""
        while i < l:
            tag = d[i]; i += 1
            field = tag >> 3; wire = tag & 0x07
            if wire == 2:
                vl, i = GoogleMigrationDecoder._varint(d, i)
                val = d[i:i+vl]; i += vl
                if field == 1: s = val
                elif field == 2: n = val.decode('utf-8', 'ignore')
                elif field == 3: iss = val.decode('utf-8', 'ignore')
            elif wire == 0: _, i = GoogleMigrationDecoder._varint(d, i)
        if not s: raise ValueError("No secret")
        sb32 = base64.b32encode(s).decode('utf-8').replace("=", "")
        disp = f"{iss} ({n})" if iss and iss not in n else n or iss
        return {"name": disp or "Unknown", "secret": sb32}

# --------------------------
# 5. 主應用程式
# --------------------------
class AuthenticatorApp:
    def __init__(self, root: tk.Tk, hidden_root: tk.Tk | None = None):
        self.root = root
        self.hidden_root = hidden_root
        self.root.title("Authenticator")

        base_w, base_h = 480, 750
        self.root.geometry(f"{S(base_w)}x{S(base_h)}")
        self.root.minsize(S(400), S(500))

        self.root.configure(bg=COLOR_BG)

        self.style = ttk.Style()
        try: self.style.theme_use('clam')
        except: pass
        self.style.configure("Horizontal.TProgressbar", background=COLOR_PRIMARY, troughcolor="#222222", borderwidth=0, thickness=S(4))

        raw = SecurityManager.decrypt_data()
        self.accounts = raw if isinstance(raw, list) else []

        self._running = True
        self._closing = False

        self.setup_ui()
        self.update_codes()

    def setup_ui(self):
        header_frame = tk.Frame(self.root, bg=COLOR_BG, pady=S(16), padx=S(16))
        header_frame.pack(fill="x")

        tk.Label(header_frame, text="Authenticator", font=FONT_TITLE, bg=COLOR_BG, fg=COLOR_TEXT_MAIN).pack(side="left")

        btn_frame = tk.Frame(header_frame, bg=COLOR_BG)
        btn_frame.pack(side="right")

        ModernButton(btn_frame, text="＋ 新增", command=self.add_account, fg=COLOR_PRIMARY,
                     font=FONT_BOLD).pack(side="left", padx=S(2))

        ModernButton(btn_frame, text="📥 匯入", command=self.import_google_qr, fg=COLOR_SUCCESS,
                     font=FONT_BOLD).pack(side="left", padx=S(2))
        
        # [修改] 使用圓形箭頭 ↻
        ModernButton(btn_frame, text="↻ 重置", command=self.factory_reset, fg=COLOR_DANGER,
                     font=FONT_BOLD).pack(side="left", padx=S(2))

        container = tk.Frame(self.root, bg=COLOR_BG)
        container.pack(fill="both", expand=True)

        self.canvas = tk.Canvas(container, bg=COLOR_BG, highlightthickness=0)
        self.scroll_frame = tk.Frame(self.canvas, bg=COLOR_BG)

        self.window_id = self.canvas.create_window((0, 0), window=self.scroll_frame, anchor="nw")
        self.canvas.bind("<Configure>", lambda e: self.canvas.itemconfig(self.window_id, width=e.width))
        self.scroll_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        self.canvas.pack(side="left", fill="both", expand=True)

        self.canvas.bind_all("<MouseWheel>", self._on_mousewheel)
        self.canvas.bind_all("<Button-4>", self._on_mousewheel)
        self.canvas.bind_all("<Button-5>", self._on_mousewheel)

        self.refresh_list()

    def factory_reset(self):
        msg = "⚠️ 警告：這將永久刪除所有帳戶資料與金鑰！\n\n此動作無法復原。\n您確定要將程式回復至初始狀態嗎？"
        if ask_confirm_dark(self.root, "危險操作確認", msg):
            try:
                self._running = False
                self.root.clipboard_clear()
                logging.shutdown()
                if BASE_DIR.exists():
                    shutil.rmtree(BASE_DIR, ignore_errors=True)
                show_message_dark(self.root, "重置完成", "所有資料已清除。\n程式將自動關閉。", False)
                self.root.destroy()
                sys.exit(0)
            except Exception as e:
                show_message_dark(self.root, "重置失敗", f"無法完全刪除檔案: {e}\n請手動刪除 {BASE_DIR}", True)

    def _on_mousewheel(self, event):
        delta = 0
        if os.name == "nt":
            delta = event.delta
        elif event.num == 4:
            delta = 120
        elif event.num == 5:
            delta = -120

        if delta == 0: return
        if self.scroll_frame.winfo_height() <= self.canvas.winfo_height(): return

        top, bottom = self.canvas.yview()
        if delta > 0 and top <= 0: return
        if delta < 0 and bottom >= 1.0: return

        try:
            if os.name == "nt":
                self.canvas.yview_scroll(int(-1*(event.delta/120)), "units")
            elif event.num == 4:
                self.canvas.yview_scroll(-1, "units")
            elif event.num == 5:
                self.canvas.yview_scroll(1, "units")
        except: pass

    def refresh_list(self):
        for w in self.scroll_frame.winfo_children(): w.destroy()
        self.code_widgets = []

        if not self.accounts:
            tk.Label(self.scroll_frame, text="尚無帳戶\n點擊右上角「新增」", font=FONT_MAIN, bg=COLOR_BG, fg=COLOR_TEXT_SUB, pady=S(100)).pack(fill="x")
            return

        for idx, acc in enumerate(self.accounts):
            self.create_account_card(idx, acc)

        tk.Frame(self.scroll_frame, bg=COLOR_BG, height=S(50)).pack(fill="x")

    def create_account_card(self, idx, acc):
        wrapper = tk.Frame(self.scroll_frame, bg=COLOR_BG)
        wrapper.pack(fill="x", padx=S(12), pady=S(6))

        card = tk.Frame(wrapper, bg=COLOR_CARD_BG, highlightthickness=1, highlightbackground=COLOR_CARD_BORDER)
        card.pack(fill="x", expand=True)

        inner = tk.Frame(card, bg=COLOR_CARD_BG, padx=S(16), pady=S(14))
        inner.pack(fill="x")

        top_row = tk.Frame(inner, bg=COLOR_CARD_BG)
        top_row.pack(fill="x")

        tk.Label(top_row, text=acc.get("name", "Unknown"), font=(FONT_FAMILY, 12, "bold"), fg=COLOR_TEXT_MAIN, bg=COLOR_CARD_BG).pack(side="left")

        del_btn = ModernButton(top_row, text="✕", command=lambda i=idx: self.delete_account(i),
                               fg=COLOR_CARD_BORDER, hover_color=COLOR_CARD_BG, font=(FONT_FAMILY, 10))
        del_btn.pack(side="right")
        del_btn.bind("<Enter>", lambda e: del_btn.config(fg=COLOR_DANGER))
        del_btn.bind("<Leave>", lambda e: del_btn.config(fg=COLOR_CARD_BORDER))

        if acc.get("issuer"):
            tk.Label(inner, text=acc["issuer"], font=(FONT_FAMILY, 10), fg=COLOR_TEXT_SUB, bg=COLOR_CARD_BG).pack(anchor="w", pady=(0, S(2)))

        code_lbl = tk.Label(inner, text="--- ---", font=FONT_CODE, fg=COLOR_PRIMARY, bg=COLOR_CARD_BG, cursor="hand2")
        code_lbl.pack(fill="x", pady=S(6))
        code_lbl.bind("<Button-1>", lambda e, l=code_lbl, s=acc["secret"]: self.copy_code(l, s))
        code_lbl.bind("<Enter>", lambda e: code_lbl.config(fg="white"))
        code_lbl.bind("<Leave>", lambda e: code_lbl.config(fg=COLOR_PRIMARY))

        progress = ttk.Progressbar(inner, orient="horizontal", length=100, mode="determinate", style="Horizontal.TProgressbar")
        progress.pack(fill="x")
        progress["maximum"] = 30

        self.code_widgets.append({"secret": acc["secret"], "label": code_lbl, "progress": progress, "copied": False})

    def update_codes(self):
        if not self._running:
            return
        try:
            now = time.time()
            rem = 30 - (now % 30)
            for item in self.code_widgets:
                item["progress"]["value"] = rem
                if not item["copied"]:
                    totp = pyotp.TOTP(item["secret"])
                    c = totp.now()
                    color = COLOR_DANGER if rem <= 5 else COLOR_PRIMARY
                    item["label"].config(text=f"{c[:3]} {c[3:]}", fg=color)
        except Exception:
            logger.exception("update_codes error")
        finally:
            if self._running:
                self.root.after(100, self.update_codes)

    def copy_code(self, label, secret):
        try:
            code = pyotp.TOTP(secret).now()
            pyperclip.copy(code)

            orig_text = label.cget("text")
            label.config(text="COPIED", fg=COLOR_SUCCESS, font=(FONT_FAMILY, 20, "bold"))
            for w in self.code_widgets:
                if w["label"] == label: w["copied"] = True

            def restore():
                label.config(text=orig_text, font=FONT_CODE)
                for w in self.code_widgets:
                    if w["label"] == label: w["copied"] = False

            self.root.after(800, restore)
        except Exception as e:
            show_message_dark(self.root, "錯誤", str(e), True)

    def add_account(self):
        name = ask_string_dark(self.root, "新增帳戶", "請輸入服務名稱:")
        if not name: return
        secret = ask_string_dark(self.root, "新增帳戶", "請輸入 Base32 金鑰:")
        if not secret: return

        try:
            pyotp.TOTP(secret.replace(" ", "").upper()).now()
            self.accounts.append({"name": name, "secret": secret.replace(" ", "").upper()})
            self.save()
            self.refresh_list()
        except:
            show_message_dark(self.root, "錯誤", "金鑰格式無效", True)

    def import_google_qr(self):
        url = ask_string_dark(self.root, "匯入", "請貼上 otpauth-migration:// 連結:")
        if not url: return
        try:
            new = GoogleMigrationDecoder.decode(url)
            exist = {a["secret"] for a in self.accounts}
            cnt = 0
            for a in new:
                s = a["secret"].replace(" ", "").upper()
                if s not in exist:
                    self.accounts.append({"name": a["name"], "secret": s})
                    exist.add(s)
                    cnt += 1
            self.save()
            self.refresh_list()
            show_message_dark(self.root, "成功", f"已匯入 {cnt} 個帳戶")
        except Exception as e:
            show_message_dark(self.root, "失敗", f"匯入錯誤: {str(e)}", True)

    def delete_account(self, idx):
        name = self.accounts[idx].get("name", "此帳戶")
        if ask_confirm_dark(self.root, "刪除確認", f"確定要移除 [{name}] 嗎？\n此動作無法復原。"):
            del self.accounts[idx]
            self.save()
            self.refresh_list()

    def save(self):
        try:
            SecurityManager.save_data_atomic(self.accounts)
        except Exception:
            logger.exception("Failed to save data on request")

    def request_close(self):
        if self._closing:
            return
        self._closing = True
        logger.info("Requesting application shutdown")
        try:
            self._running = False
            try:
                self.save()
            except Exception:
                logger.exception("Error while saving during shutdown")
            if self.hidden_root:
                try:
                    self.hidden_root.destroy()
                except Exception:
                    pass
            try:
                self.root.quit()
            except Exception:
                pass
            try:
                self.root.destroy()
            except Exception:
                pass
        except Exception:
            logger.exception("Error during shutdown")

# --------------------------
# 6. 啟動入口
# --------------------------
if __name__ == "__main__":
    try:
        migrate_legacy_files()
    except Exception as e:
        logger.error(f"Migration failed: {e}")

    parser = argparse.ArgumentParser()
    parser.add_argument("--no-windows-hello", action="store_true")
    args = parser.parse_args()

    try:
        ok, reason = asyncio.run(SecurityManager.verify_user(args.no_windows_hello))
    except KeyboardInterrupt:
        logger.info("Interrupted during verification")
        sys.exit(0)

    if not ok:
        tmp = tk.Tk()
        tmp.withdraw()
        messagebox.showerror("驗證失敗", reason, parent=tmp)
        tmp.destroy()
        sys.exit(1)

    try:
        SecurityManager.load_key()
    except Exception as e:
        tmp = tk.Tk()
        tmp.withdraw()
        messagebox.showerror("嚴重錯誤", f"金鑰重置失敗，請檢查權限: {e}", parent=tmp)
        tmp.destroy()
        sys.exit(1)

    root = tk.Tk()
    app = AuthenticatorApp(root, None)
    root.protocol("WM_DELETE_WINDOW", app.request_close)

    def _signal_handler(signum, frame):
        try:
            root.after(0, app.request_close)
        except Exception:
            try:
                app.request_close()
            except Exception:
                pass

    for s in (signal.SIGINT, signal.SIGTERM):
        try:
            signal.signal(s, _signal_handler)
        except Exception:
            pass
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, _signal_handler)
        except Exception:
            pass

    try:
        root.mainloop()
    finally:
        try:
            app.request_close()
        except Exception:
            pass