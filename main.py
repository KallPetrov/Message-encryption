import os
import base64
import zipfile
import customtkinter as ctk
from tkinter import filedialog, messagebox
from cryptography.fernet import Fernet
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes

# Настройки
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")

keys = {}
fernet_key = Fernet.generate_key()
fernet = Fernet(fernet_key)

def pad(data):
    return data + (16 - len(data) % 16) * chr(16 - len(data) % 16)

def unpad(data):
    return data[:-ord(data[-1])]

def encrypt_file():
    file_path = filedialog.askopenfilename(title="Select file to encrypt")
    if not file_path:
        return
    method = method_var.get()
    bits = int(bits_var.get())
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if method == "Fernet":
            messagebox.showwarning("Unsupported", "Fernet does not support file encryption.")
            return
        elif method == "AES":
            if bits not in [128, 192, 256]:
                raise ValueError("AES supports 128, 192, or 256 bit keys.")
            key = get_random_bytes(bits // 8)
            cipher = AES.new(key, AES.MODE_EAX)
            ciphertext, tag = cipher.encrypt_and_digest(data)
            with open(file_path + ".enc", 'wb') as f:
                f.write(cipher.nonce + tag + ciphertext)
            with open(file_path + ".key", 'wb') as f:
                f.write(key)
            messagebox.showinfo("Success", f"Encrypted: {file_path}.enc")
        elif method == "RSA":
            if bits < 512:
                raise ValueError("RSA must be at least 512 bits.")
            rsa_key = RSA.generate(bits)
            keys["rsa_file_private"] = rsa_key
            public_key = rsa_key.publickey()
            cipher = PKCS1_OAEP.new(public_key)
            encrypted = cipher.encrypt(data)
            with open(file_path + ".enc", 'wb') as f:
                f.write(encrypted)
            with open("rsa_file_public.pem", 'wb') as f:
                f.write(public_key.export_key())
            with open("rsa_file_private.pem", 'wb') as f:
                f.write(rsa_key.export_key())
            messagebox.showinfo("Success", f"Encrypted with RSA: {file_path}.enc")
    except Exception as e:
        messagebox.showerror("Error", f"Encryption failed: {str(e)}")

def decrypt_file():
    file_path = filedialog.askopenfilename(title="Select encrypted file", filetypes=[("Encrypted", "*.enc")])
    if not file_path:
        return
    method = method_var.get()
    bits = int(bits_var.get())
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        if method == "AES":
            key_path = file_path.replace(".enc", ".key")
            if not os.path.exists(key_path):
                raise FileNotFoundError("Missing key file!")
            with open(key_path, 'rb') as f:
                key = f.read()
            nonce, tag, ciphertext = data[:16], data[16:32], data[32:]
            cipher = AES.new(key, AES.MODE_EAX, nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            save_path = filedialog.asksaveasfilename(title="Save decrypted file")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(plaintext)
                messagebox.showinfo("Success", f"Decrypted: {save_path}")
        elif method == "RSA":
            if "rsa_file_private" not in keys:
                raise ValueError("RSA private key missing!")
            private_key = keys["rsa_file_private"]
            cipher = PKCS1_OAEP.new(private_key)
            decrypted = cipher.decrypt(data)
            save_path = filedialog.asksaveasfilename(title="Save decrypted file")
            if save_path:
                with open(save_path, 'wb') as f:
                    f.write(decrypted)
                messagebox.showinfo("Success", f"Decrypted: {save_path}")
        else:
            messagebox.showwarning("Unsupported", "Fernet not supported for decryption.")
    except Exception as e:
        messagebox.showerror("Error", f"Decryption failed: {str(e)}")

def encrypt_folder():
    folder_path = filedialog.askdirectory(title="Select folder to encrypt")
    if not folder_path:
        return
    method = method_var.get()
    if method == "Fernet":
        messagebox.showwarning("Unsupported", "Fernet does not support folders.")
        return
    zip_filename = folder_path + ".zip"
    with zipfile.ZipFile(zip_filename, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for root, _, files in os.walk(folder_path):
            for file in files:
                zipf.write(os.path.join(root, file), os.path.relpath(os.path.join(root, file), folder_path))
    encrypt_file_from_path(zip_filename)

def encrypt_file_from_path(path):
    global method_var, bits_var
    method = method_var.get()
    bits = int(bits_var.get())
    with open(path, 'rb') as f:
        data = f.read()
    if method == "AES":
        key = get_random_bytes(bits // 8)
        cipher = AES.new(key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        with open(path + ".enc", 'wb') as f:
            f.write(cipher.nonce + tag + ciphertext)
        with open(path + ".key", 'wb') as f:
            f.write(key)
        messagebox.showinfo("Success", f"Folder encrypted as ZIP: {path}.enc")

def decrypt_folder():
    decrypt_file()
    file_path = filedialog.askopenfilename(title="Select .zip file", filetypes=[("ZIP Files", "*.zip")])
    if not file_path:
        return
    extract_path = filedialog.askdirectory(title="Where to extract")
    if extract_path:
        with zipfile.ZipFile(file_path, 'r') as zipf:
            zipf.extractall(extract_path)
        messagebox.showinfo("Success", "Folder decrypted and extracted.")

# --- GUI Setup ---
app = ctk.CTk()
app.title("🔐 Cryptography by Hexagon Lab")
app.geometry("600x400")

ctk.CTkLabel(app, text="Select Encryption Method:").pack(pady=(20, 5))
method_var = ctk.StringVar(value="AES")
method_menu = ctk.CTkComboBox(app, variable=method_var, values=["AES", "RSA", "Fernet"])
method_menu.pack()

ctk.CTkLabel(app, text="Select Key Length:").pack(pady=(20, 5))
bits_var = ctk.StringVar(value="256")
bits_menu = ctk.CTkComboBox(app, variable=bits_var,
                            values=["128", "192", "256", "512", "1024", "2048", "4096"])
bits_menu.pack()

btn_frame = ctk.CTkFrame(app)
btn_frame.pack(pady=30)

ctk.CTkButton(btn_frame, text="📁 Encrypt File", command=encrypt_file).grid(row=0, column=0, padx=10, pady=10)
ctk.CTkButton(btn_frame, text="📂 Decrypt File", command=decrypt_file).grid(row=0, column=1, padx=10, pady=10)
ctk.CTkButton(btn_frame, text="🗂 Encrypt Folder", command=encrypt_folder).grid(row=1, column=0, padx=10, pady=10)
ctk.CTkButton(btn_frame, text="🗂 Decrypt Folder", command=decrypt_folder).grid(row=1, column=1, padx=10, pady=10)

app.mainloop()
