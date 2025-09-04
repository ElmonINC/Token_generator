import tkinter as tk
from tkinter import messagebox
import secrets
import string

def generate_token():
    length = int(length_entry.get())
    alphabet = string.ascii_letters + string.digits + string.punctuation
    token = ''.join(secrets.choice(alphabet) for _ in range(length))
    token_output.delete(0, tk.END)
    token_output.insert(0, token)

def copy_token():
    token = token_output.get()
    if token:
        root.clipboard_clear()
        root.clipboard_append(token)
        messagebox.showinfo("Copied", "Token copied to clipboard!")

# GUI setup
root = tk.Tk()
root.title("Token Generator")

tk.Label(root, text="Token Length:").grid(row=0, column=0, padx=10, pady=10)
length_entry = tk.Entry(root)
length_entry.grid(row=0, column=1, padx=10, pady=10)
length_entry.insert(0, "32")  # default length

tk.Button(root, text="Generate Token", command=generate_token).grid(row=1, column=0, columnspan=2, pady=10)

token_output = tk.Entry(root, width=50)
token_output.grid(row=2, column=0, columnspan=2, padx=10, pady=10)

tk.Button(root, text="Copy Token", command=copy_token).grid(row=3, column=0, columnspan=2, pady=10)

root.mainloop()
