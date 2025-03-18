import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
import binascii
import json
import struct
import sqlite3
from datetime import datetime
import hashlib
import secrets
import base64
from Crypto.Hash import SHA256, SHA3_512
from Crypto.Protocol.KDF import PBKDF2
import re

class SecureFileEncryption:
    def __init__(self):
        self.root = None
        self.current_user = None
        self.login_window = None
        self.encryption_window = None
        self.selected_files = []

        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(base_dir, '../database')
        os.makedirs(db_dir, exist_ok=True)
        self.db_file = os.path.join(db_dir, 'database.db')
        
        self.initialize_database()
    
    def initialize_database(self):
        conn = sqlite3.connect(self.db_file)
        cursor = conn.cursor()

        # Create or update users table with enhanced schema
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                password_iterations INTEGER NOT NULL,
                account_locked INTEGER DEFAULT 0,
                lock_until TEXT DEFAULT NULL,
                last_password_change TEXT,
                login_attempts INTEGER DEFAULT 0
            )
        ''')

        cursor.execute("PRAGMA table_info(users)")
        columns = [column[1] for column in cursor.fetchall()]
        if "salt" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN salt TEXT NOT NULL DEFAULT ''")
        if "account_locked" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN account_locked INTEGER DEFAULT 0")
        if "lock_until" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN lock_until TEXT DEFAULT NULL")
        if "last_password_change" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN last_password_change TEXT")
        if "login_attempts" not in columns:
            cursor.execute("ALTER TABLE users ADD COLUMN login_attempts INTEGER DEFAULT 0")

        conn.commit()
        conn.close()
    
    def hash_password(self, password, salt=None, iterations=100000):
        if salt is None:
            salt = secrets.token_hex(32)
        key = PBKDF2(password.encode(), salt.encode(), dkLen=32, count=iterations, hmac_hash_module=SHA256)
        password_hash = base64.b64encode(key).decode('utf-8')
        return password_hash, salt, iterations

    def validate_password_strength(self, password):
        if len(password) < 12:
            return False, "Password must be at least 12 characters long"
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(not c.isalnum() for c in password)
        if not (has_upper and has_lower and has_digit and has_special):
            return False, "Password must contain uppercase, lowercase letters, numbers, and special characters"
        common_passwords = ["password", "123456", "qwerty", "admin"]
        if any(common in password.lower() for common in common_passwords):
            return False, "Password contains common patterns that are easily guessed"
        return True, "Password meets strength requirements"

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')
    
    def register(self):
        reg_window = tk.Toplevel(self.root)
        reg_window.title("Register")
        self.center_window(reg_window, 600, 500)
        reg_window.grab_set()

        title_label = tk.Label(reg_window, text="User Registration", font=("Helvetica", 16, "bold"))
        title_label.pack(pady=(20, 10))

        tk.Label(reg_window, text="Username:").pack(pady=(10,5))
        username_entry = tk.Entry(reg_window, width=40, font=("Arial", 14))
        username_entry.pack(pady=5)
        username_entry.focus_set()

        tk.Label(reg_window, text="Password:").pack(pady=(5,5))
        password_entry = tk.Entry(reg_window, show="*", width=40, font=("Arial", 14))
        password_entry.pack(pady=5)

        strength_var = tk.StringVar(value="Password strength: Not evaluated")
        strength_label = tk.Label(reg_window, textvariable=strength_var)
        strength_label.pack(pady=5)

        tk.Label(reg_window, text="Confirm Password:").pack(pady=(5,5))
        confirm_password_entry = tk.Entry(reg_window, show="*", width=40, font=("Arial", 14))
        confirm_password_entry.pack(pady=5)

        req_frame = ttk.LabelFrame(reg_window, text="Password Requirements")
        req_frame.pack(fill=tk.X, padx=20, pady=10)
        requirements_text = (
            "• At least 12 characters long\n"
            "• Contains uppercase and lowercase letters\n"
            "• Contains numbers\n"
            "• Contains special characters\n"
            "• Must not be a common password"
        )
        reqs_label = tk.Label(req_frame, text=requirements_text, justify=tk.LEFT)
        reqs_label.pack(padx=10, pady=5, anchor=tk.W)

        def check_password_strength(event=None):
            password = password_entry.get()
            if not password:
                strength_var.set("Password strength: Not evaluated")
                return
            valid, message = self.validate_password_strength(password)
            if valid:
                strength_var.set("Password strength: Strong")
                strength_label.config(fg="green")
            else:
                strength_var.set("Password strength: Weak - " + message)
                strength_label.config(fg="red")
        password_entry.bind("<KeyRelease>", check_password_strength)

        def register_user():
            username = username_entry.get()
            password = password_entry.get()
            confirm_password = confirm_password_entry.get()
            if not username or not password or not confirm_password:
                messagebox.showerror("Error", "Please fill in all fields")
                return
            if not re.match(r"^[A-Za-z0-9_]{4,}$", username):
                messagebox.showerror("Error", "Username must be at least 4 characters long and can contain letters, numbers, and underscores")
                return
            valid, msg = self.validate_password_strength(password)
            if not valid:
                messagebox.showerror("Error", msg)
                return
            if password != confirm_password:
                messagebox.showerror("Error", "Passwords do not match")
                return

            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
            if cursor.fetchone():
                messagebox.showerror("Error", "Username already exists")
                conn.close()
                return

            password_hash, salt, iterations = self.hash_password(password)
            current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "INSERT INTO users (username, password_hash, salt, password_iterations, last_password_change) VALUES (?, ?, ?, ?, ?)",
                (username, password_hash, salt, iterations, current_time)
            )
            conn.commit()
            conn.close()
            
            messagebox.showinfo("Success", "Registration successful")
            reg_window.destroy()

        register_button = tk.Button(reg_window, text="Register", command=register_user, width=20, height=2)
        register_button.pack(pady=10)
        reg_window.bind('<Return>', lambda event: register_user())
    
    def login(self):
        if self.login_window is None or not self.login_window.winfo_exists():
            self.login_window = tk.Toplevel(self.root)
            self.login_window.title("Login")
            self.center_window(self.login_window, 500, 400)
            self.login_window.grab_set()

            title_label = tk.Label(self.login_window, text="Secure File Encryption Login", 
                               font=("Helvetica", 16, "bold"))
            title_label.pack(pady=(20, 10))

            tk.Label(self.login_window, text="Username:").pack(pady=(10,5))
            username_entry = tk.Entry(self.login_window, width=40, font=("Arial", 14))
            username_entry.pack(ipady=5, pady=10)
            username_entry.focus_set()

            tk.Label(self.login_window, text="Password:").pack(pady=(10,5))
            password_entry = tk.Entry(self.login_window, width=40, font=("Arial", 14), show="*")
            password_entry.pack(ipady=5, pady=10)

            def validate_login():
                username = username_entry.get()
                password = password_entry.get()

                conn = sqlite3.connect(self.db_file)
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash, salt, password_iterations FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                conn.close()

                if not result:
                    messagebox.showerror("Error", "User not found")
                    return

                stored_hash, salt, iterations = result
                calculated_hash, _, _ = self.hash_password(password, salt, iterations)
                if stored_hash == calculated_hash:
                    self.current_user = username
                    self.login_window.destroy()
                    self.login_window = None
                    self.open_encryption_window()
                else:
                    messagebox.showerror("Error", "Incorrect password")

            tk.Button(self.login_window, text="Login", command=validate_login, width=20, height=2).pack(pady=10)
            self.login_window.bind('<Return>', lambda event: validate_login())
        else:
            self.login_window.lift()

    def copy_key(self, entry_widget):
        key_text = entry_widget.get().strip()
        if key_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(key_text)
            self.status_label.config(text="Key copied to clipboard")
        else:
            self.status_label.config(text="No key to copy")

    def delete_key(self, entry_widget):
        entry_widget.delete(0, tk.END)
        self.status_label.config(text="Key deleted")

    def open_encryption_window(self):
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return

        self.encryption_window = tk.Toplevel(self.root)
        self.encryption_window.title(f"Secure File Encryption - {self.current_user}")
        self.center_window(self.encryption_window, 1000, 700) 

        self.key_type = tk.StringVar(value="kyber")

        key_frame = ttk.LabelFrame(self.encryption_window, text="Key Management", padding=10)
        key_frame.pack(fill="x", padx=10, pady=5)

        key_type_frame = ttk.Frame(key_frame)
        key_type_frame.pack(fill="x", pady=5)
        
        ttk.Label(key_type_frame, text="Select Key Type:").pack(side="left", padx=5)

        ttk.Radiobutton(key_type_frame, text="Kyber Key", variable=self.key_type, 
                       value="kyber", command=self.toggle_key_fields).pack(side="left", padx=5)
        
        ttk.Radiobutton(key_type_frame, text="Quantum Key", variable=self.key_type, 
                       value="quantum", command=self.toggle_key_fields).pack(side="left", padx=5)
        
        ttk.Radiobutton(key_type_frame, text="Hybrid Key", variable=self.key_type, 
                    value="hybrid", command=self.toggle_key_fields).pack(side="left", padx=5)

        self.key_input_frame = ttk.Frame(key_frame)
        self.key_input_frame.pack(fill="x", pady=10)

        self.kyber_frame = ttk.Frame(self.key_input_frame)
        self.kyber_frame.pack(fill="x", pady=2)
        ttk.Label(self.kyber_frame, text="Kyber Key:").pack(side="left", padx=5)
        self.kyber_entry = ttk.Entry(self.kyber_frame, width=60, font=("Arial", 14))
        self.kyber_entry.pack(side="left", padx=5)

        ttk.Button(self.kyber_frame, text="Copy", command=lambda: self.copy_key(self.kyber_entry)).pack(side="left", padx=2)
        ttk.Button(self.kyber_frame, text="Delete", command=lambda: self.delete_key(self.kyber_entry)).pack(side="left", padx=2)

        self.quantum_frame = ttk.Frame(self.key_input_frame)
        self.quantum_frame.pack(fill="x", pady=2)
        ttk.Label(self.quantum_frame, text="Quantum Key:").pack(side="left", padx=5)
        self.quantum_entry = ttk.Entry(self.quantum_frame, width=60, font=("Arial", 14))
        self.quantum_entry.pack(side="left", padx=5)

        ttk.Button(self.quantum_frame, text="Copy", command=lambda: self.copy_key(self.quantum_entry)).pack(side="left", padx=2)
        ttk.Button(self.quantum_frame, text="Delete", command=lambda: self.delete_key(self.quantum_entry)).pack(side="left", padx=2)

        self.hybrid_frame = ttk.Frame(self.key_input_frame)
        self.hybrid_frame.pack(fill="x", pady=2)
        ttk.Label(self.hybrid_frame, text="Hybrid Key:").pack(side="left", padx=5)
        self.hybrid_entry = ttk.Entry(self.hybrid_frame, width=60, font=("Arial", 14))
        self.hybrid_entry.pack(side="left", padx=5)

        ttk.Button(self.hybrid_frame, text="Copy", command=lambda: self.copy_key(self.hybrid_entry)).pack(side="left", padx=2)
        ttk.Button(self.hybrid_frame, text="Delete", command=lambda: self.delete_key(self.hybrid_entry)).pack(side="left", padx=2)

        self.toggle_key_fields()

        file_frame = ttk.LabelFrame(self.encryption_window, text="File Operations", padding=10)
        file_frame.pack(fill="both", expand=True, padx=10, pady=5)

        style = ttk.Style()
        style.configure('Large.TButton', padding=(20, 10))

        button_frame = ttk.Frame(file_frame)
        button_frame.pack(pady=10)
        
        ttk.Button(button_frame, text="Choose Files", 
                  command=self.choose_files, 
                  style='Large.TButton',
                  width=30).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Encrypt Selected Files", 
                  command=self.encrypt_files, 
                  style='Large.TButton',
                  width=30).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Decrypt Files", 
                  command=self.decrypt_files, 
                  style='Large.TButton',
                  width=30).pack(side=tk.LEFT, padx=5)
        
        ttk.Button(button_frame, text="Back to Login", 
                  command=self.back_to_login, 
                  style='Large.TButton',
                  width=20).pack(side=tk.LEFT, padx=5)

        file_list_frame = ttk.Frame(file_frame)
        file_list_frame.pack(fill="both", expand=True, pady=10)
        
        file_list_label = ttk.Label(file_list_frame, text="Selected Files:")
        file_list_label.pack(anchor="w", padx=5, pady=5)
        
        tree_frame = ttk.Frame(file_list_frame)
        tree_frame.pack(fill="both", expand=True)
        
        yscrollbar = ttk.Scrollbar(tree_frame, orient="vertical")
        yscrollbar.pack(side="right", fill="y")
        
        xscrollbar = ttk.Scrollbar(tree_frame, orient="horizontal")
        xscrollbar.pack(side="bottom", fill="x")
        
        self.file_tree = ttk.Treeview(
            tree_frame, 
            columns=("filename", "filetype", "size"),
            show="headings",
            yscrollcommand=yscrollbar.set,
            xscrollcommand=xscrollbar.set
        )
        
        yscrollbar.config(command=self.file_tree.yview)
        xscrollbar.config(command=self.file_tree.xview)
        
        self.file_tree.heading("filename", text="File Name")
        self.file_tree.heading("filetype", text="File Type")
        self.file_tree.heading("size", text="Size (bytes)")
        
        self.file_tree.column("filename", width=400, minwidth=200)
        self.file_tree.column("filetype", width=100, minwidth=80)
        self.file_tree.column("size", width=100, minwidth=80)
        
        self.file_tree.pack(fill="both", expand=True)
        
        self.status_label = ttk.Label(self.encryption_window, text="")
        self.status_label.pack(pady=10)

    def back_to_login(self):
        """Return to login screen"""
        self.encryption_window.destroy()
        self.encryption_window = None
        self.current_user = None
        self.login()

    def toggle_key_fields(self):
        if self.key_type.get() == "kyber":
            self.kyber_entry.configure(state="normal")
            self.quantum_entry.configure(state="disabled")
            self.hybrid_entry.configure(state="disabled")
            self.quantum_entry.delete(0, tk.END)
            self.hybrid_entry.delete(0, tk.END)
        elif self.key_type.get() == "quantum":
            self.kyber_entry.configure(state="disabled")
            self.quantum_entry.configure(state="normal")
            self.hybrid_entry.configure(state="disabled")
            self.kyber_entry.delete(0, tk.END)
            self.hybrid_entry.delete(0, tk.END)
        else:  
            self.kyber_entry.configure(state="disabled")
            self.quantum_entry.configure(state="disabled")
            self.hybrid_entry.configure(state="normal")
            self.kyber_entry.delete(0, tk.END)
            self.quantum_entry.delete(0, tk.END)

    def get_current_key(self):
        key_type = self.key_type.get()
        if key_type == "kyber":
            key_str = self.kyber_entry.get().strip()
            if not key_str:
                raise ValueError("Please enter a Kyber key")
            try:
                key_bytes = binascii.unhexlify(key_str)
            except binascii.Error:
                raise ValueError("Invalid hex format for Kyber secret")
            derived_key = PBKDF2(key_bytes, b"file_encryption_salt", dkLen=32, count=100000, hmac_hash_module=SHA3_512)
            return derived_key
        elif key_type == "quantum":
            key_str = self.quantum_entry.get().strip()
            if not key_str:
                raise ValueError("Please enter a Quantum key")
            if not all(c in '01' for c in key_str):
                raise ValueError("Quantum key must contain only 0s and 1s")
            key_int = int(key_str, 2)
            key_bytes = key_int.to_bytes((len(key_str) + 7) // 8, byteorder='big')
            derived_key = PBKDF2(key_bytes, b"file_encryption_salt", dkLen=32, count=100000, hmac_hash_module=SHA3_512)
            return derived_key
        else:  # hybrid
            key_str = self.hybrid_entry.get().strip()
            if not key_str:
                raise ValueError("Please enter a Hybrid key")
            key_bytes = key_str.encode()
            derived_key = PBKDF2(key_bytes, b"file_encryption_salt", dkLen=32, count=100000, hmac_hash_module=SHA3_512)
            return derived_key

    def encrypt_file(self, file_path, key):
        with open(file_path, 'rb') as f:
            data = f.read()
        
        nonce = get_random_bytes(12)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        filename_bytes = os.path.basename(file_path).encode()
        cipher.update(filename_bytes)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        metadata = {
            'filename': os.path.basename(file_path),
            'nonce': binascii.hexlify(nonce).decode(),
            'tag': binascii.hexlify(tag).decode()
        }
        
        metadata_bytes = json.dumps(metadata).encode()
        metadata_length = len(metadata_bytes)
        
        return struct.pack('<I', metadata_length) + metadata_bytes + ciphertext

    def decrypt_file(self, encrypted_data, key):
        try:
            metadata_length = struct.unpack('<I', encrypted_data[:4])[0]
            metadata = json.loads(encrypted_data[4:4+metadata_length].decode())
            
            ciphertext = encrypted_data[4+metadata_length:]
            
            nonce = binascii.unhexlify(metadata['nonce'])
            tag = binascii.unhexlify(metadata['tag'])
            cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
            
            cipher.update(metadata['filename'].encode())
            
            data = cipher.decrypt_and_verify(ciphertext, tag)
            return data, metadata['filename']
            
        except Exception as e:
            raise ValueError(f"Decryption failed: {str(e)}")
    
    def choose_files(self):
        files = filedialog.askopenfilenames(
            title="Select Files",
            filetypes=[("All Files", "*.*")]
        )
        
        if not files:
            return
            
        self.selected_files = files
        
        for item in self.file_tree.get_children():
            self.file_tree.delete(item)
        
        for file_path in self.selected_files:
            filename = os.path.basename(file_path)
            filetype = os.path.splitext(filename)[1]
            if not filetype:
                filetype = "No extension"
            else:
                filetype = filetype[1:].upper()
            try:
                size = os.path.getsize(file_path)
            except:
                size = "Unknown"
                
            self.file_tree.insert("", "end", values=(filename, filetype, size))
        
        self.status_label.config(text=f"Selected {len(files)} files")
    
    def encrypt_files(self):
        if not hasattr(self, 'selected_files') or not self.selected_files:
            messagebox.showerror("Error", "Please select files first")
            return
            
        try:
            key = self.get_current_key()
            
            save_dir = filedialog.askdirectory(title="Select Directory to Save Encrypted Files")
            if not save_dir:
                return
            
            for file_path in self.selected_files:
                encrypted_data = self.encrypt_file(file_path, key)
                output_path = os.path.join(save_dir, f"{os.path.basename(file_path)}.encrypted")
                with open(output_path, 'wb') as f:
                    f.write(encrypted_data)
            
            self.status_label.config(text="Files encrypted successfully!")
            messagebox.showinfo("Success", "Files encrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")
    
    def decrypt_files(self):
        try:
            key = self.get_current_key()
            
            files = filedialog.askopenfilenames(
                title="Select Encrypted Files",
                filetypes=[("Encrypted Files", "*.encrypted")]
            )
            
            if not files:
                return
            
            for item in self.file_tree.get_children():
                self.file_tree.delete(item)
            
            for file_path in files:
                filename = os.path.basename(file_path)
                filetype = "ENCRYPTED"
                try:
                    size = os.path.getsize(file_path)
                except:
                    size = "Unknown"
                self.file_tree.insert("", "end", values=(filename, filetype, size))
            
            self.status_label.config(text=f"Selected {len(files)} files for decryption")
            
            save_dir = filedialog.askdirectory(title="Select Directory to Save Decrypted Files")
            if not save_dir:
                return
            
            for encrypted_file in files:
                with open(encrypted_file, 'rb') as f:
                    encrypted_data = f.read()
                
                decrypted_data, original_filename = self.decrypt_file(encrypted_data, key)
                
                output_path = os.path.join(save_dir, original_filename)
                with open(output_path, 'wb') as f:
                    f.write(decrypted_data)
            
            self.status_label.config(text="Files decrypted successfully!")
            messagebox.showinfo("Success", "Files decrypted successfully!")
            
        except Exception as e:
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def main(self):
        self.root = tk.Tk()
        self.root.title("Secure File Encryption System")
        self.center_window(self.root, 800, 600)

        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.place(relx=0.5, rely=0.5, anchor="center")

        title_label = tk.Label(main_frame, text="Quantum-Secure File Encryption System", 
                           font=("Helvetica", 26, "bold"))
        title_label.pack(pady=(0, 20))

        subtitle_label = tk.Label(main_frame, text="Ensuring Your Data Stays Secure At Rest & in Transit", 
                            font=("Helvetica", 14))
        subtitle_label.pack(pady=(0, 40))

        login_button = ttk.Button(main_frame, text="Login", command=self.login, width=25)
        login_button.pack(pady=10, ipadx=50, ipady=10)
        
        register_button = ttk.Button(main_frame, text="Register", command=self.register, width=25)
        register_button.pack(pady=10, ipadx=50, ipady=10)

        self.root.mainloop()

if __name__ == "__main__":
    app = SecureFileEncryption()
    app.main()
