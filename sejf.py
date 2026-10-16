# -*- coding: utf-8 -*-
"""
СЕЙФ — личный шифровальщик файлов и заметок.

Алгоритм: AES-256-GCM (шифрование + проверка целостности).
Ключ получается из твоего пароля через scrypt (стойкий к перебору).
Пароль нигде не хранится — без него данные не восстановить НИКАК,
поэтому запомни его или запиши в надёжном месте.

Запуск:  python sejf.py   (или двойной клик по "Запустить Сейф.bat")
"""

import os
import struct
import secrets

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext

# --- проверка, что установлена библиотека cryptography ---
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.exceptions import InvalidTag
except ImportError:
    import sys
    msg = ("Не установлена библиотека 'cryptography'.\n\n"
           "Установи её командой:\n"
           "    pip install cryptography\n\n"
           "Или запусти файл 'Запустить Сейф.bat' — он поставит всё сам.")
    try:
        r = tk.Tk(); r.withdraw()
        messagebox.showerror("Сейф — нет библиотеки", msg)
    except Exception:
        print(msg)
    sys.exit(1)


# ======================= КРИПТО-ЯДРО =======================

MAGIC = b"SEJF1\x00"      # метка формата (6 байт)
SALT_LEN = 16            # соль для scrypt
NONCE_LEN = 12           # одноразовый вектор для AES-GCM
KEY_LEN = 32             # 256-битный ключ
SCRYPT_N = 2 ** 17       # параметры scrypt (чем больше N, тем дольше перебор)
SCRYPT_R = 8
SCRYPT_P = 1


def _derive_key(password: str, salt: bytes) -> bytes:
    """Из пароля + соли делаем 256-битный ключ через scrypt."""
    kdf = Scrypt(salt=salt, length=KEY_LEN, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(password.encode("utf-8"))


def encrypt_bytes(password: str, plaintext: bytes, name: bytes = b"") -> bytes:
    """Шифруем произвольные байты. В начало кладём имя файла (для восстановления)."""
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    payload = struct.pack(">H", len(name)) + name + plaintext
    ciphertext = aes.encrypt(nonce, payload, None)
    return MAGIC + salt + nonce + ciphertext


def decrypt_bytes(password: str, blob: bytes):
    """Расшифровываем. Возвращает (имя_файла_bytes, данные_bytes).
    Бросает ValueError при неверном формате и InvalidTag при неверном пароле."""
    if blob[:6] != MAGIC:
        raise ValueError("Это не файл Сейфа (неверный формат).")
    off = 6
    salt = blob[off:off + SALT_LEN]; off += SALT_LEN
    nonce = blob[off:off + NONCE_LEN]; off += NONCE_LEN
    ciphertext = blob[off:]
    key = _derive_key(password, salt)
    aes = AESGCM(key)
    payload = aes.decrypt(nonce, ciphertext, None)  # InvalidTag -> неверный пароль
    name_len = struct.unpack(">H", payload[:2])[0]
    name = payload[2:2 + name_len]
    data = payload[2 + name_len:]
    return name, data


# ======================= ИНТЕРФЕЙС =======================

class SejfApp:
    def __init__(self, root):
        self.root = root
        root.title("🔒 Сейф — шифрование данных")
        root.geometry("640x560")
        root.minsize(560, 500)

        # --- общий пароль сверху ---
        top = ttk.LabelFrame(root, text="Мастер-пароль")
        top.pack(fill="x", padx=12, pady=(12, 6))

        self.pw_var = tk.StringVar()
        self.show_var = tk.BooleanVar(value=False)
        self.pw_entry = ttk.Entry(top, textvariable=self.pw_var, show="•", width=40)
        self.pw_entry.pack(side="left", padx=8, pady=8)
        ttk.Checkbutton(top, text="показать", variable=self.show_var,
                        command=self._toggle_pw).pack(side="left", padx=4)
        ttk.Label(top, text="(без него данные не вернуть!)",
                  foreground="#b00").pack(side="left", padx=8)

        # --- вкладки ---
        nb = ttk.Notebook(root)
        nb.pack(fill="both", expand=True, padx=12, pady=6)
        nb.add(self._build_files_tab(nb), text="  Файлы  ")
        nb.add(self._build_notes_tab(nb), text="  Заметка  ")

        # --- строка статуса ---
        self.status = tk.StringVar(value="Готов. Введи пароль и выбери действие.")
        ttk.Label(root, textvariable=self.status, relief="sunken",
                  anchor="w").pack(fill="x", side="bottom")

    def _toggle_pw(self):
        self.pw_entry.config(show="" if self.show_var.get() else "•")

    def _password(self):
        pw = self.pw_var.get()
        if not pw:
            messagebox.showwarning("Сейф", "Сначала введи мастер-пароль.")
            return None
        return pw

    # ---------- вкладка «Файлы» ----------
    def _build_files_tab(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Зашифровать файл → получится копия с расширением .sejf\n"
                          "Расшифровать .sejf → вернётся исходный файл",
                  justify="left").pack(anchor="w", padx=10, pady=12)

        ttk.Button(f, text="🔒  Зашифровать файл…",
                   command=self.encrypt_file).pack(fill="x", padx=40, pady=6)
        ttk.Button(f, text="🔓  Расшифровать файл (.sejf)…",
                   command=self.decrypt_file).pack(fill="x", padx=40, pady=6)

        self.del_orig = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="после шифрования удалять исходный файл",
                        variable=self.del_orig).pack(anchor="w", padx=40, pady=(14, 0))
        return f

    def encrypt_file(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.askopenfilename(title="Выбери файл для шифрования")
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                data = fh.read()
            name = os.path.basename(path).encode("utf-8")
            blob = encrypt_bytes(pw, data, name)
            out = path + ".sejf"
            with open(out, "wb") as fh:
                fh.write(blob)
            if self.del_orig.get():
                os.remove(path)
            self.status.set(f"Зашифровано → {out}")
            messagebox.showinfo("Сейф", f"Файл зашифрован:\n{out}")
        except Exception as e:
            messagebox.showerror("Ошибка шифрования", str(e))

    def decrypt_file(self):
        pw = self._password()
        if not pw:
            return
        path = filedialog.askopenfilename(
            title="Выбери .sejf файл",
            filetypes=[("Файлы Сейфа", "*.sejf"), ("Все файлы", "*.*")])
        if not path:
            return
        try:
            with open(path, "rb") as fh:
                blob = fh.read()
            name, data = decrypt_bytes(pw, blob)
            folder = os.path.dirname(path)
            orig = name.decode("utf-8") if name else os.path.basename(path)[:-5]
            out = os.path.join(folder, orig)
            if os.path.exists(out):
                base, ext = os.path.splitext(out)
                out = base + "_расшифровано" + ext
            with open(out, "wb") as fh:
                fh.write(data)
            self.status.set(f"Расшифровано → {out}")
            messagebox.showinfo("Сейф", f"Файл расшифрован:\n{out}")
        except InvalidTag:
            messagebox.showerror("Сейф", "Неверный пароль или файл повреждён.")
        except ValueError as e:
            messagebox.showerror("Сейф", str(e))
        except Exception as e:
            messagebox.showerror("Ошибка расшифровки", str(e))

    # ---------- вкладка «Заметка» ----------
    def _build_notes_tab(self, parent):
        f = ttk.Frame(parent)
        ttk.Label(f, text="Напиши текст (пароли, коды, записи) и зашифруй его в строку.\n"
                          "Зашифрованную строку можно хранить где угодно; "
                          "расшифровать — только с мастер-паролем.",
                  justify="left").pack(anchor="w", padx=10, pady=(12, 6))

        self.note = scrolledtext.ScrolledText(f, height=12, wrap="word")
        self.note.pack(fill="both", expand=True, padx=10, pady=6)

        row = ttk.Frame(f); row.pack(fill="x", padx=10, pady=6)
        ttk.Button(row, text="🔒 Зашифровать текст",
                   command=self.encrypt_note).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(row, text="🔓 Расшифровать текст",
                   command=self.decrypt_note).pack(side="left", expand=True, fill="x", padx=4)
        ttk.Button(row, text="Очистить",
                   command=lambda: self.note.delete("1.0", "end")).pack(side="left", padx=4)
        return f

    def encrypt_note(self):
        import base64
        pw = self._password()
        if not pw:
            return
        text = self.note.get("1.0", "end-1c")
        if not text:
            return
        try:
            blob = encrypt_bytes(pw, text.encode("utf-8"))
            b64 = base64.b64encode(blob).decode("ascii")
            self.note.delete("1.0", "end")
            self.note.insert("1.0", b64)
            self.status.set("Текст зашифрован (можно копировать и хранить).")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))

    def decrypt_note(self):
        import base64
        pw = self._password()
        if not pw:
            return
        b64 = self.note.get("1.0", "end-1c").strip()
        if not b64:
            return
        try:
            blob = base64.b64decode(b64)
            _, data = decrypt_bytes(pw, blob)
            self.note.delete("1.0", "end")
            self.note.insert("1.0", data.decode("utf-8"))
            self.status.set("Текст расшифрован.")
        except InvalidTag:
            messagebox.showerror("Сейф", "Неверный пароль или текст повреждён.")
        except Exception as e:
            messagebox.showerror("Ошибка", "Не удалось расшифровать:\n" + str(e))


def main():
    root = tk.Tk()
    try:
        style = ttk.Style()
        style.theme_use("clam")
    except Exception:
        pass
    SejfApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
