import os
import sys
import json
import random
import string
import tempfile
import subprocess
import requests
import webbrowser
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import pyperclip
import qrcode
from barcode import Code128
from barcode.writer import ImageWriter
from PIL import Image, ImageTk
from cryptography.fernet import Fernet

# -------------------------------
# App Metadata
# -------------------------------
APP_NAME = "ElGen"
APP_VERSION = "1.1.0"
GITHUB_REPO = "https://github.com/ElmonINC/Token_generator.git"  # Replace with your GitHub repo


# -------------------------------
# Token Generator
# -------------------------------
def generate_token(length=16, letters=True, numbers=True):
    chars = ""
    if letters:
        chars += string.ascii_letters
    if numbers:
        chars += string.digits
    return "".join(random.choice(chars) for _ in range(length))


# -------------------------------
# QR & Barcode Generator
# -------------------------------
def generate_qr(data, logo_path=None, save_path=None, file_format="PNG"):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_H)
    qr.add_data(data)
    qr.make(fit=True)
    img = qr.make_image(fill="black", back_color="white").convert("RGB")

    if logo_path and os.path.exists(logo_path):
        logo = Image.open(logo_path)
        qr_width, qr_height = img.size
        logo_size = qr_width // 5
        logo = logo.resize((logo_size, logo_size))
        pos = ((qr_width - logo_size) // 2, (qr_height - logo_size) // 2)
        img.paste(logo, pos)

    if save_path:
        img.save(save_path, file_format)
    return img


def generate_barcode(data, save_path=None, file_format="PNG"):
    code = Code128(data, writer=ImageWriter())
    if save_path:
        code.save(save_path)
    return code


# -------------------------------
# Update Checker
# -------------------------------
def check_for_updates(auto=True, log=None):
    try:
        url = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"
        r = requests.get(url, timeout=5)
        if r.status_code != 200:
            return
        release = r.json()
        latest_version = release["tag_name"].lstrip("v")

        if latest_version > APP_VERSION:
            if sys.platform.startswith("win") or sys.platform.startswith("linux"):
                if messagebox.askyesno("Update Available", f"New version {latest_version} available.\nDownload now?"):
                    asset = release["assets"][0]["browser_download_url"]
                    download_and_replace(asset, log)
            elif sys.platform == "darwin":
                messagebox.showinfo("Update Available", f"New version {latest_version} available.\n\nDownload manually.")
                webbrowser.open(release["html_url"])
    except Exception as e:
        if not auto:
            messagebox.showerror("Update Error", str(e))
        if log:
            log(f"[Error] Update failed: {e}")


def download_and_replace(asset_url, log=None):
    exe_path = sys.executable
    tmp_file = tempfile.mktemp(suffix=os.path.basename(exe_path))

    if log:
        log(f"[Update] Downloading update from {asset_url}")

    with requests.get(asset_url, stream=True) as r:
        with open(tmp_file, "wb") as f:
            for chunk in r.iter_content(chunk_size=8192):
                f.write(chunk)

    os.replace(tmp_file, exe_path)
    if log:
        log("[Update] Update complete, restarting app.")
    subprocess.Popen([exe_path])
    sys.exit(0)


# -------------------------------
# Encryption Utility
# -------------------------------
def generate_key():
    return Fernet.generate_key()


def encrypt_message(message, key):
    return Fernet(key).encrypt(message.encode()).decode()


def decrypt_message(token, key):
    return Fernet(key).decrypt(token.encode()).decode()


# -------------------------------
# GUI App
# -------------------------------
class SecureTokenApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("700x600")
        self.logo_path = "logo.png"
        self.developer_mode = tk.BooleanVar(value=False)
        self.auto_update_enabled = tk.BooleanVar(value=True)

        self.build_ui()
        self.after(2000, lambda: check_for_updates(auto=True, log=self.log_message))

    def build_ui(self):
        # Header
        header = ttk.Frame(self)
        header.pack(fill="x", pady=10)
        if os.path.exists(self.logo_path):
            logo = Image.open(self.logo_path).resize((40, 40))
            self.logo_img = ImageTk.PhotoImage(logo)
            ttk.Label(header, image=self.logo_img).pack(side="left", padx=10)
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 16, "bold")).pack(side="left")

        # Token Section
        token_frame = ttk.LabelFrame(self, text="Token Generator")
        token_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(token_frame, text="Length:").pack(side="left", padx=5)
        self.length_var = tk.IntVar(value=16)
        ttk.Entry(token_frame, textvariable=self.length_var, width=5).pack(side="left")

        ttk.Button(token_frame, text="Generate", command=self.make_token).pack(side="left", padx=5)
        ttk.Button(token_frame, text="Copy", command=self.copy_token).pack(side="left", padx=5)

        self.token_var = tk.StringVar()
        ttk.Entry(token_frame, textvariable=self.token_var, width=40).pack(side="left", padx=5)

        # QR/Barcode Section
        qr_frame = ttk.LabelFrame(self, text="QR / Barcode Generator")
        qr_frame.pack(fill="x", padx=10, pady=10)

        ttk.Label(qr_frame, text="Data:").pack(anchor="w", padx=5)
        self.data_var = tk.StringVar()
        ttk.Entry(qr_frame, textvariable=self.data_var, width=50).pack(padx=5, pady=5)

        btns = ttk.Frame(qr_frame)
        btns.pack()
        ttk.Button(btns, text="Generate QR", command=self.make_qr).pack(side="left", padx=5)
        ttk.Button(btns, text="Generate Barcode", command=self.make_barcode).pack(side="left", padx=5)

        # Developer Mode
        dev_toggle = ttk.Checkbutton(self, text="Developer Mode", variable=self.developer_mode, command=self.build_dev_ui)
        dev_toggle.pack(pady=5)

        # Log console
        self.log_text = tk.Text(self, height=5, state="disabled", bg="black", fg="lime")
        self.log_text.pack(fill="x", padx=10, pady=5)

    def build_dev_ui(self):
        if self.developer_mode.get():
            dev_frame = ttk.LabelFrame(self, text="Developer Options")
            dev_frame.pack(fill="x", padx=10, pady=10)

            # Bulk Token
            ttk.Button(dev_frame, text="Generate 50 Tokens", command=lambda: self.bulk_tokens(50)).pack(side="left", padx=5)
            ttk.Button(dev_frame, text="Generate 100 Tokens", command=lambda: self.bulk_tokens(100)).pack(side="left", padx=5)

            # Update Controls
            ttk.Checkbutton(dev_frame, text="Auto-update on startup", variable=self.auto_update_enabled).pack(side="left", padx=5)
            ttk.Button(dev_frame, text="Check Update Now", command=lambda: check_for_updates(auto=False, log=self.log_message)).pack(side="left", padx=5)

            # Encryption Test
            enc_frame = ttk.LabelFrame(dev_frame, text="Encrypt / Decrypt")
            enc_frame.pack(fill="x", padx=10, pady=10)

            self.enc_key = generate_key()
            self.enc_input = tk.StringVar()
            self.enc_output = tk.StringVar()

            ttk.Entry(enc_frame, textvariable=self.enc_input, width=30).pack(side="left", padx=5)
            ttk.Button(enc_frame, text="Encrypt", command=self.do_encrypt).pack(side="left", padx=5)
            ttk.Button(enc_frame, text="Decrypt", command=self.do_decrypt).pack(side="left", padx=5)
            ttk.Entry(enc_frame, textvariable=self.enc_output, width=30).pack(side="left", padx=5)

    # --- Token ---
    def make_token(self):
        token = generate_token(self.length_var.get())
        self.token_var.set(token)

    def copy_token(self):
        pyperclip.copy(self.token_var.get())
        messagebox.showinfo("Copied", "Token copied to clipboard.")

    def bulk_tokens(self, count):
        tokens = [generate_token(self.length_var.get()) for _ in range(count)]
        path = filedialog.asksaveasfilename(defaultextension=".txt")
        if path:
            with open(path, "w") as f:
                for t in tokens:
                    f.write(t + "\n")
            messagebox.showinfo("Saved", f"{count} tokens saved at {path}")

    # --- QR / Barcode ---
    def make_qr(self):
        data = self.data_var.get().strip()
        if not data:
            return messagebox.showwarning("Error", "Enter some data.")
        save_path = filedialog.asksaveasfilename(defaultextension=".png")
        if save_path:
            img = generate_qr(data, logo_path=self.logo_path, save_path=save_path)
            messagebox.showinfo("Saved", f"QR Code saved at {save_path}")

    def make_barcode(self):
        data = self.data_var.get().strip()
        if not data:
            return messagebox.showwarning("Error", "Enter some data.")
        save_path = filedialog.asksaveasfilename(defaultextension=".png")
        if save_path:
            generate_barcode(data, save_path=save_path)
            messagebox.showinfo("Saved", f"Barcode saved at {save_path}")

    # --- Encryption ---
    def do_encrypt(self):
        text = self.enc_input.get()
        if not text:
            return
        self.enc_output.set(encrypt_message(text, self.enc_key))
        self.log_message("[Encrypt] Message encrypted.")

    def do_decrypt(self):
        token = self.enc_input.get()
        try:
            self.enc_output.set(decrypt_message(token, self.enc_key))
            self.log_message("[Decrypt] Message decrypted.")
        except Exception as e:
            self.log_message(f"[Error] {e}")

    # --- Logger ---
    def log_message(self, msg):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", msg + "\n")
        self.log_text.configure(state="disabled")
        self.log_text.see("end")


if __name__ == "__main__":
    app = SecureTokenApp()
    app.mainloop()
