from cx_Freeze import setup, Executable
import sys

APP_NAME = "ElGen"
APP_VERSION = "1.1.0"
DESCRIPTION = "Token, QR, and Barcode Generator"
AUTHOR = "ELMON"

# Dependencies (auto-detected, but we can add extras)
build_exe_options = {
    "packages": ["os", "tkinter", "qrcode", "barcode", "cryptography", "pyperclip", "requests", "PIL"],
    "include_files": ["logo.png"],
    "optimize": 2,
}

# Base setup
base = None
if sys.platform == "win32":
    base = "Win32GUI"  # prevents cmd window from opening

setup(
    name=APP_NAME,
    version=APP_VERSION,
    description=DESCRIPTION,
    author=AUTHOR,
    options={"build_exe": build_exe_options},
    executables=[Executable("app.py", base=base, icon="logo.ico")],
)
