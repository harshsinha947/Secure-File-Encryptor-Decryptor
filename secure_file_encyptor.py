import tkinter as tk
from tkinter import filedialog, messagebox
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes
import hashlib
import os

# --- Helper Functions ---
def derive_key(password, salt):
    """Generate a 32-byte AES key from password and salt"""
    return PBKDF2(password, salt, dkLen=32, count=1000000)

def encrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        salt = get_random_bytes(16)
        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(data)

        # Store original filename
        filename = os.path.basename(file_path).encode()
        filename_len = len(filename).to_bytes(2, 'big')  # 2 bytes for length

        encrypted_file = file_path + ".enc"
        with open(encrypted_file, "wb") as f:
            f.write(salt + cipher.nonce + tag + filename_len + filename + ciphertext)

        hash_value = hashlib.sha256(data).hexdigest()
        return encrypted_file, hash_value
    except Exception as e:
        return None, str(e)

def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            raw = f.read()

        salt = raw[:16]
        nonce = raw[16:32]
        tag = raw[32:48]
        filename_len = int.from_bytes(raw[48:50], 'big')
        filename = raw[50:50+filename_len].decode()
        ciphertext = raw[50+filename_len:]

        key = derive_key(password, salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted_data = cipher.decrypt_and_verify(ciphertext, tag)

        # Save decrypted file with original filename in same folder
        decrypted_file = os.path.join(os.path.dirname(file_path), filename)
        with open(decrypted_file, "wb") as f:
            f.write(decrypted_data)

        hash_value = hashlib.sha256(decrypted_data).hexdigest()
        return decrypted_file, hash_value
    except Exception as e:
        return None, str(e)

# --- GUI Functions ---
def select_file():
    file_path = filedialog.askopenfilename()
    file_entry.delete(0, tk.END)
    file_entry.insert(0, file_path)

def handle_encrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter password.")
        return
    encrypted_file, file_hash = encrypt_file(file_path, password)
    if encrypted_file:
        hash_text.config(state="normal")
        hash_text.delete("1.0", tk.END)
        hash_text.insert(tk.END, f"Encrypted File: {encrypted_file}\nSHA-256: {file_hash}")
        hash_text.config(state="disabled")
        messagebox.showinfo("Success", "File Encrypted Successfully!")
    else:
        messagebox.showerror("Error", f"Encryption failed: {file_hash}")

def handle_decrypt():
    file_path = file_entry.get()
    password = password_entry.get()
    if not file_path or not password:
        messagebox.showerror("Error", "Please select a file and enter password.")
        return
    decrypted_file, file_hash = decrypt_file(file_path, password)
    if decrypted_file:
        hash_text.config(state="normal")
        hash_text.delete("1.0", tk.END)
        hash_text.insert(tk.END, f"Decrypted File: {decrypted_file}\nSHA-256: {file_hash}")
        hash_text.config(state="disabled")
        messagebox.showinfo("Success", "File Decrypted Successfully!")
    else:
        messagebox.showerror("Error", f"Decryption failed: {file_hash}")

def clear_all():
    file_entry.delete(0, tk.END)
    password_entry.delete(0, tk.END)
    hash_text.config(state="normal")
    hash_text.delete("1.0", tk.END)
    hash_text.config(state="disabled")

# --- GUI Setup ---
root = tk.Tk()
root.title("🔐 Advanced File Encryptor")
root.geometry("700x400")
root.configure(bg="#1c1c1c")

# Title
title_label = tk.Label(root, text="Secure File Encryption & Hashing", font=("Helvetica", 18, "bold"),
                       fg="#00ff99", bg="#1c1c1c")
title_label.pack(pady=15)

# Frame for file and password
main_frame = tk.Frame(root, bg="#2c2c2c", bd=2, relief="ridge")
main_frame.pack(pady=10, padx=20, fill="x")

# File selection
tk.Label(main_frame, text="Select File:", font=("Helvetica", 12), fg="white", bg="#2c2c2c").grid(row=0, column=0, pady=10, padx=10, sticky="w")
file_entry = tk.Entry(main_frame, width=50, bg="#3c3c3c", fg="white", insertbackground="white")
file_entry.grid(row=0, column=1, padx=5)
tk.Button(main_frame, text="Browse", command=select_file, bg="#0984e3", fg="white").grid(row=0, column=2, padx=5)

# Password entry
tk.Label(main_frame, text="Password:", font=("Helvetica", 12), fg="white", bg="#2c2c2c").grid(row=1, column=0, pady=10, padx=10, sticky="w")
password_entry = tk.Entry(main_frame, show="*", width=50, bg="#3c3c3c", fg="white", insertbackground="white")
password_entry.grid(row=1, column=1, columnspan=2, pady=5)

# Buttons
btn_frame = tk.Frame(root, bg="#1c1c1c")
btn_frame.pack(pady=15)
btn_style = {"width":15, "font":("Helvetica", 12), "bd":0, "relief":"ridge"}

tk.Button(btn_frame, text="Encrypt File", command=handle_encrypt, bg="#00b894", fg="white", **btn_style).grid(row=0, column=0, padx=10)
tk.Button(btn_frame, text="Decrypt File", command=handle_decrypt, bg="#0984e3", fg="white", **btn_style).grid(row=0, column=1, padx=10)
tk.Button(btn_frame, text="Clear", command=clear_all, bg="#d63031", fg="white", **btn_style).grid(row=0, column=2, padx=10)

# Hash / result output
hash_label = tk.Label(root, text="File Info & SHA-256 Hash:", font=("Helvetica", 12), fg="white", bg="#1c1c1c")
hash_label.pack()
hash_text = tk.Text(root, height=6, width=80, bg="#2c2c2c", fg="white", insertbackground="white", state="disabled")
hash_text.pack(pady=5)

# Footer
footer = tk.Label(root, text="Developed by [Your Name] | AES-256 Encryption & SHA-256 Hash",
                  font=("Helvetica", 10), fg="gray", bg="#1c1c1c")
footer.pack(side="bottom", pady=10)

root.mainloop()
