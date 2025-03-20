import tkinter as tk 
from tkinter import messagebox, scrolledtext, ttk
import sqlite3
import os
import base64
from datetime import datetime, timedelta
import hashlib
import secrets
import time
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA3_512, HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
import re
import cffi
from argon2.low_level import hash_secret_raw, Type # type: ignore
# from cffi import hash_secret_raw, Type

class QuantumKeyManagementSystem:
    def __init__(self):
        self.root = None
        self.current_user = None
        self.login_window = None
        self.kms_window = None
        self.session_start_time = None
        self.max_session_duration = 30 * 60  

        self.quantum_key = None
        self.kyber_key = None
        self.hybrid_key = None

        base_dir = os.path.dirname(os.path.abspath(__file__))
        db_dir = os.path.join(base_dir, '../database')
        os.makedirs(db_dir, exist_ok=True)
        self.db_file = os.path.join(db_dir, 'database.db')
        self.setup_database()

    def initialize_database(self):
        """Create database tables (users, quantum_keys, audit_log, hybrid_keys) and handle migrations"""
        conn = self.get_db_connection()
        cursor = conn.cursor()

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

        cursor.execute("PRAGMA table_info(quantum_keys)")
        columns = [column[1] for column in cursor.fetchall()]

        if not columns:  
            cursor.execute('''
                CREATE TABLE quantum_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    key_name TEXT NOT NULL DEFAULT 'Unnamed Key',
                    encrypted_key TEXT NOT NULL,
                    key_hmac TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    date_created TEXT NOT NULL,
                    time_created TEXT NOT NULL,
                    action TEXT NOT NULL,
                    key_type TEXT NOT NULL DEFAULT 'quantum',
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
        elif 'key_hmac' not in columns:
            cursor.execute('''
                CREATE TABLE quantum_keys_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL,
                    key_name TEXT NOT NULL DEFAULT 'Unnamed Key',
                    encrypted_key TEXT NOT NULL,
                    key_hmac TEXT NOT NULL,
                    salt TEXT NOT NULL,
                    iv TEXT NOT NULL,
                    date_created TEXT NOT NULL,
                    time_created TEXT NOT NULL,
                    action TEXT NOT NULL,
                    key_type TEXT NOT NULL DEFAULT 'quantum',
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
            cursor.execute('DROP TABLE quantum_keys')
            cursor.execute('ALTER TABLE quantum_keys_new RENAME TO quantum_keys')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                action TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT,
                details TEXT
            )
        ''')

        cursor.execute('''
            CREATE TABLE IF NOT EXISTS hybrid_keys (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                key_name TEXT NOT NULL,
                encrypted_key TEXT NOT NULL,
                key_hmac TEXT NOT NULL,
                salt TEXT NOT NULL,
                iv TEXT NOT NULL,
                date_created TEXT NOT NULL,
                time_created TEXT NOT NULL,
                quantum_key_id INTEGER,
                kyber_key_id INTEGER,
                FOREIGN KEY (username) REFERENCES users(username),
                FOREIGN KEY (quantum_key_id) REFERENCES quantum_keys(id),
                FOREIGN KEY (kyber_key_id) REFERENCES quantum_keys(id)
            )
        ''')

        conn.commit()
        conn.close()

    def setup_database(self):
        if os.path.exists(self.db_file):
            self.initialize_database()
        else:
            self.initialize_database()

    def get_db_connection(self):
        conn = sqlite3.connect(self.db_file)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.text_factory = str
        return conn

    def log_audit(self, action, details=None):
        username = self.current_user if self.current_user else "anonymous"
        conn = self.get_db_connection()
        cursor = conn.cursor()
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ip_address = "127.0.0.1"  
        cursor.execute(
            "INSERT INTO audit_log (username, action, timestamp, ip_address, details) VALUES (?, ?, ?, ?, ?)",
            (username, action, timestamp, ip_address, details)
        )
        conn.commit()
        conn.close()

    def hash_password(self, password, salt=None, iterations=100000):
        if salt is None:
            salt = secrets.token_hex(32)
        key = PBKDF2(password.encode(), salt.encode(), dkLen=32, count=iterations, hmac_hash_module=SHA256)
        password_hash = base64.b64encode(key).decode('utf-8')
        return password_hash, salt, iterations

    def verify_password(self, stored_hash, stored_salt, iterations, provided_password):
        calculated_hash, _, _ = self.hash_password(provided_password, stored_salt, iterations)
        return secrets.compare_digest(calculated_hash, stored_hash)

    def encrypt_quantum_key(self, password, quantum_key):
        try:
            salt = secrets.token_hex(32)
            key_hash, _, _ = self.hash_password(password, salt)
            key = base64.b64decode(key_hash)
            iv = get_random_bytes(16)
            cipher = AES.new(key, AES.MODE_CBC, iv)
            padded_data = pad(quantum_key.encode(), AES.block_size)
            ciphertext = cipher.encrypt(padded_data)
            h = HMAC.new(key, digestmod=SHA256)
            h.update(iv + ciphertext)
            hmac_digest = h.digest()
            encrypted_key_b64 = base64.b64encode(ciphertext).decode('utf-8')
            hmac_b64 = base64.b64encode(hmac_digest).decode('utf-8')
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            return encrypted_key_b64, hmac_b64, salt, iv_b64
        except Exception as e:
            messagebox.showerror("Encryption Error", "Failed to encrypt key")
            self.log_audit("encryption_error", str(e))
            return None

    def decrypt_quantum_key(self, password, encrypted_key, hmac_value, salt, iv_b64):
        try:
            key_hash, _, _ = self.hash_password(password, salt)
            key = base64.b64decode(key_hash)
            ciphertext = base64.b64decode(encrypted_key)
            stored_hmac = base64.b64decode(hmac_value)
            iv = base64.b64decode(iv_b64)
            h = HMAC.new(key, digestmod=SHA256)
            h.update(iv + ciphertext)
            calculated_hmac = h.digest()
            if not secrets.compare_digest(calculated_hmac, stored_hmac):
                messagebox.showerror("Security Error", "Data integrity verification failed. The key may have been tampered with.")
                self.log_audit("integrity_failure", "HMAC verification failed during decryption")
                return None
            cipher = AES.new(key, AES.MODE_CBC, iv)
            decrypted = unpad(cipher.decrypt(ciphertext), AES.block_size)
            return decrypted.decode()
        except Exception as e:
            messagebox.showerror("Decryption Error", "Incorrect password or corrupted key")
            self.log_audit("decryption_error", str(e))
            return None

    def center_window(self, window, width, height):
        screen_width = window.winfo_screenwidth()
        screen_height = window.winfo_screenheight()
        x = (screen_width // 2) - (width // 2)
        y = (screen_height // 2) - (height // 2)
        window.geometry(f'{width}x{height}+{x}+{y}')

    def check_session_timeout(self):
        if self.session_start_time and self.current_user:
            current_time = time.time()
            elapsed_time = current_time - self.session_start_time
            if elapsed_time > self.max_session_duration:
                messagebox.showwarning("Session Timeout", "Your session has expired for security reasons.")
                self.log_audit("session_timeout", f"Session timeout after {elapsed_time} seconds")
                self.logout()
                return True
            self.kms_window.after(60000, self.check_session_timeout)
        return False

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
                strength_var.set(f"Password strength: Weak - {message}")
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
            password_hash, salt, iterations = self.hash_password(password)
            conn = self.get_db_connection()
            cursor = conn.cursor()
            try:
                cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
                if cursor.fetchone():
                    messagebox.showerror("Error", "Username already exists")
                    conn.close()
                    return
                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(
                    "INSERT INTO users (username, password_hash, salt, password_iterations, last_password_change) VALUES (?, ?, ?, ?, ?)",
                    (username, password_hash, salt, iterations, current_time)
                )
                conn.commit()
                self.log_audit("user_registered", f"New user registered: {username}")
                messagebox.showinfo("Success", "Registration successful")
                reg_window.destroy()
            except sqlite3.Error as e:
                conn.rollback()
                messagebox.showerror("Database Error", "Registration failed")
                self.log_audit("registration_error", str(e))
            finally:
                conn.close()
        tk.Button(reg_window, text="Register", command=register_user, width=20, height=2).pack(pady=10)

    def check_account_lockout(self, username):
        conn = self.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT account_locked, lock_until, login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return False
        is_locked, lock_until, attempts = result
        if is_locked:
            if lock_until:
                lock_time = datetime.strptime(lock_until, "%Y-%m-%d %H:%M:%S")
                current_time = datetime.now()
                if current_time > lock_time:
                    cursor.execute("UPDATE users SET account_locked = 0, lock_until = NULL WHERE username = ?", (username,))
                    conn.commit()
                    conn.close()
                    return False
                else:
                    remaining_minutes = int((lock_time - current_time).total_seconds() / 60)
                    conn.close()
                    messagebox.showerror("Account Locked", f"This account is temporarily locked. Please try again in {remaining_minutes} minutes.")
                    return True
        conn.close()
        return False

    def increment_failed_attempts(self, username):
        conn = self.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT login_attempts FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            conn.close()
            return
        attempts = result[0] + 1
        if attempts >= 5:
            lock_until = (datetime.now() + timedelta(minutes=30)).strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute(
                "UPDATE users SET account_locked = 1, lock_until = ?, login_attempts = ? WHERE username = ?",
                (lock_until, attempts, username)
            )
            self.log_audit("account_locked", f"Account locked after {attempts} failed attempts: {username}")
        else:
            cursor.execute("UPDATE users SET login_attempts = ? WHERE username = ?", (attempts, username))
        conn.commit()
        conn.close()

    def reset_login_attempts(self, username):
        conn = self.get_db_connection()
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET login_attempts = 0 WHERE username = ?", (username,))
        conn.commit()
        conn.close()

    def login(self):
        if self.login_window is None or not self.login_window.winfo_exists():
            self.login_window = tk.Toplevel(self.root)
            self.login_window.title("Login")
            self.center_window(self.login_window, 500, 400)
            self.login_window.grab_set()

            title_label = tk.Label(self.login_window, text="Key Management System Login", font=("Helvetica", 16, "bold"))
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
                if not username or not password:
                    messagebox.showerror("Error", "Please enter both username and password")
                    return
                if self.check_account_lockout(username):
                    return
                conn = self.get_db_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT password_hash, salt, password_iterations FROM users WHERE username = ?", (username,))
                result = cursor.fetchone()
                conn.close()
                if not result:
                    messagebox.showerror("Error", "Invalid username or password")
                    self.log_audit("failed_login", f"Attempt with invalid username: {username}")
                    return
                stored_hash, salt, iterations = result
                time.sleep(0.2)  # Mitigate timing attacks
                if self.verify_password(stored_hash, salt, iterations, password):
                    self.reset_login_attempts(username)
                    self.current_user = username
                    self.session_start_time = time.time()
                    self.log_audit("successful_login", f"User logged in: {username}")
                    self.login_window.destroy()
                    self.login_window = None
                    self.open_key_management()
                else:
                    messagebox.showerror("Error", "Invalid username or password")
                    self.increment_failed_attempts(username)
                    self.log_audit("failed_login", f"Failed login attempt for user: {username}")
            login_button = tk.Button(self.login_window, text="Login", command=validate_login, width=20, height=2)
            login_button.pack(pady=10)
            self.login_window.bind('<Return>', lambda event: validate_login())
        else:
            self.login_window.lift()

    def logout(self):
        if self.current_user:
            self.log_audit("logout", f"User logged out: {self.current_user}")
            self.current_user = None
            self.session_start_time = None
            self.quantum_key = None
            self.kyber_key = None
            self.hybrid_key = None
            if self.kms_window and self.kms_window.winfo_exists():
                self.kms_window.destroy()
                self.kms_window = None

    def password_prompt(self, title, action_callback):
        password_window = tk.Toplevel(self.kms_window)
        password_window.title(title)
        self.center_window(password_window, 450, 250)
        password_window.grab_set()

        tk.Label(password_window, text="Enter Password:").pack(pady=(10,5))
        password_entry = tk.Entry(password_window, show="*", font=("Arial", 14), width=30)
        password_entry.pack(pady=5)
        password_entry.focus_set()

        attempts = [0]

        def verify_password():
            if attempts[0] >= 3:
                messagebox.showerror("Error", "Too many incorrect attempts")
                password_window.destroy()
                return
            pwd = password_entry.get()
            if not pwd:
                messagebox.showerror("Error", "Please enter your password")
                return
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT password_hash, salt, password_iterations FROM users WHERE username = ?", (self.current_user,))
            result = cursor.fetchone()
            conn.close()
            if not result:
                messagebox.showerror("Error", "User account error")
                password_window.destroy()
                return
            stored_hash, salt, iterations = result
            if self.verify_password(stored_hash, salt, iterations, pwd):
                password_window.destroy()
                action_callback(pwd)
            else:
                attempts[0] += 1
                remaining = 3 - attempts[0]
                messagebox.showerror("Error", f"Incorrect password. {remaining} attempts remaining.")
                self.log_audit("password_verification_failed", "Failed password verification in action dialog")
        submit_btn = tk.Button(password_window, text="Submit", command=verify_password, width=25, height=2)
        submit_btn.pack(pady=10)
        password_window.bind('<Return>', lambda event: verify_password())

    def open_key_management(self):
        if not self.current_user:
            messagebox.showerror("Error", "Please login first")
            return

        self.kms_window = tk.Toplevel(self.root)
        self.kms_window.title(f"Key Management System - {self.current_user}")
        self.center_window(self.kms_window, 1200, 800)
        self.kms_window.after(60000, self.check_session_timeout)

        notebook = ttk.Notebook(self.kms_window)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        key_management_frame = ttk.Frame(notebook)
        hybrid_key_frame = ttk.Frame(notebook)
        notebook.add(key_management_frame, text="Key Management")
        notebook.add(hybrid_key_frame, text="Hybrid Key Generation")

        key_input_frame = ttk.LabelFrame(key_management_frame, text="Key Input")
        key_input_frame.pack(fill=tk.X, padx=10, pady=10)

        key_type_frame = ttk.Frame(key_input_frame)
        key_type_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(key_type_frame, text="Key Type:").pack(side=tk.LEFT, padx=5)
        key_type_var = tk.StringVar(value="quantum")
        quantum_radio = ttk.Radiobutton(key_type_frame, text="Quantum Key", variable=key_type_var, value="quantum")
        kyber_radio = ttk.Radiobutton(key_type_frame, text="Kyber Key", variable=key_type_var, value="kyber")
        quantum_radio.pack(side=tk.LEFT, padx=10)
        kyber_radio.pack(side=tk.LEFT, padx=10)

        key_name_frame = ttk.Frame(key_input_frame)
        key_name_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(key_name_frame, text="Key Name:").pack(side=tk.LEFT, padx=5)
        key_name_entry = tk.Entry(key_name_frame, font=("Arial", 14))
        key_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        tk.Label(key_input_frame, text="Enter your Key to secure:").pack(anchor=tk.W, padx=15, pady=5)
        quantum_key_entry = scrolledtext.ScrolledText(key_input_frame, height=5)
        quantum_key_entry.pack(fill=tk.X, padx=15, pady=5)

        password_frame = ttk.Frame(key_input_frame)
        password_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(password_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        password_entry = tk.Entry(password_frame, show="*", font=("Arial", 14))
        password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        history_frame = ttk.LabelFrame(key_management_frame, text="Key History")
        history_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        history_scrollbar = ttk.Scrollbar(history_frame, orient=tk.VERTICAL)
        history_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        history_table = ttk.Treeview(history_frame, 
                                     columns=("ID", "Key Name", "Type", "Date", "Time", "Action"), 
                                     show="headings", 
                                     yscrollcommand=history_scrollbar.set)
        history_table.heading("ID", text="ID")
        history_table.heading("Key Name", text="Key Name")
        history_table.heading("Type", text="Type")
        history_table.heading("Date", text="Date")
        history_table.heading("Time", text="Time")
        history_table.heading("Action", text="Action")
        history_table.column("ID", width=50)
        history_table.column("Key Name", width=150)
        history_table.column("Type", width=100)
        history_table.column("Date", width=100)
        history_table.column("Time", width=100)
        history_table.column("Action", width=100)
        history_table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        history_scrollbar.config(command=history_table.yview)

        def load_user_keys():
            for item in history_table.get_children():
                history_table.delete(item)
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, key_name, key_type, date_created, time_created, action 
                FROM quantum_keys 
                WHERE username = ?
                ORDER BY date_created DESC, time_created DESC
            """, (self.current_user,))
            for row in cursor.fetchall():
                history_table.insert("", "end", values=row)
            conn.close()

        def encrypt_key():
            key_name = key_name_entry.get().strip()
            key_content = quantum_key_entry.get("1.0", tk.END).strip()
            pwd = password_entry.get()
            key_type = key_type_var.get()
            if not key_name or not key_content or not pwd:
                messagebox.showerror("Error", "Please enter key name, key content, and password")
                return
            if key_type == "quantum":
                if not all(bit in "01" for bit in key_content):
                    messagebox.showerror("Error", "Quantum key must contain only 0s and 1s")
                    return
            elif key_type == "kyber":
                try:
                    int(key_content, 16)
                except ValueError:
                    messagebox.showerror("Error", "Kyber key must be a valid hexadecimal value")
                    return
            result = self.encrypt_quantum_key(pwd, key_content)
            if result:
                encrypted_key, key_hmac, salt, iv_b64 = result
                conn = self.get_db_connection()
                cursor = conn.cursor()
                current_date = datetime.now().strftime("%Y-%m-%d")
                current_time = datetime.now().strftime("%H:%M:%S")
                cursor.execute("""
                    INSERT INTO quantum_keys (username, key_name, encrypted_key, key_hmac, salt, iv, date_created, time_created, action, key_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (self.current_user, key_name, encrypted_key, key_hmac, salt, iv_b64, current_date, current_time, 'Encrypt', key_type))
                conn.commit()
                new_id = cursor.lastrowid
                conn.close()
                history_table.insert("", 0, values=(new_id, key_name, key_type, current_date, current_time, 'Encrypt'))
                messagebox.showinfo("Success", "Your key has been encrypted and stored securely")
                key_name_entry.delete(0, tk.END)
                quantum_key_entry.delete("1.0", tk.END)
                password_entry.delete(0, tk.END)

        def decrypt_key():
            selected = history_table.selection()
            if not selected:
                messagebox.showerror("Error", "Please select a key to decrypt")
                return
            values = history_table.item(selected[0])['values']
            key_id = values[0]
            key_name = values[1]
            key_type = values[2]
            conn = self.get_db_connection()
            cursor = conn.cursor()
            cursor.execute("""
                SELECT encrypted_key, key_hmac, salt, iv 
                FROM quantum_keys 
                WHERE id = ? AND username = ?
            """, (key_id, self.current_user))
            result = cursor.fetchone()
            conn.close()
            if not result:
                messagebox.showerror("Error", "Key not found")
                return
            encrypted_key, key_hmac, salt, iv_b64 = result

            def perform_decryption(pwd):
                decrypted = self.decrypt_quantum_key(pwd, encrypted_key, key_hmac, salt, iv_b64)
                if decrypted:
                    decrypt_window = tk.Toplevel(self.kms_window)
                    decrypt_window.title(f"Decrypt Key - {key_name}")
                    self.center_window(decrypt_window, 600, 300)
                    tk.Label(decrypt_window, text=f"Decrypted Key: {key_name}", font=("Helvetica", 14, "bold")).pack(pady=(20,10))
                    tk.Label(decrypt_window, text=f"Key Type: {key_type.capitalize()}").pack(pady=5)
                    text_area = scrolledtext.ScrolledText(decrypt_window, height=5)
                    text_area.insert(tk.END, decrypted)
                    text_area.config(state=tk.DISABLED)
                    text_area.pack(padx=10, pady=10, fill=tk.X)
                    button_frame = tk.Frame(decrypt_window)
                    button_frame.pack(pady=5, fill=tk.X)

                    def copy_key():
                        decrypt_window.clipboard_clear()
                        decrypt_window.clipboard_append(decrypted)
                        messagebox.showinfo("Copied", "Key copied to clipboard")
                        self.kms_window.after(30000, lambda: self.kms_window.clipboard_clear())

                    def use_for_hybrid():
                        if key_type == "quantum":
                            self.quantum_key = decrypted
                        elif key_type == "kyber":
                            self.kyber_key = decrypted
                        update_hybrid_key_displays()
                        notebook.select(hybrid_key_frame)
                        decrypt_window.destroy()
                    tk.Button(button_frame, text="Copy Key", command=copy_key, width=15).pack(side=tk.LEFT, padx=10)
                    tk.Button(button_frame, text="Use for Hybrid Key Gen", command=use_for_hybrid, width=20).pack(side=tk.LEFT, padx=10)
                    conn2 = self.get_db_connection()
                    cursor2 = conn2.cursor()
                    current_date = datetime.now().strftime("%Y-%m-%d")
                    current_time = datetime.now().strftime("%H:%M:%S")
                    cursor2.execute("""
                        INSERT INTO quantum_keys (username, key_name, encrypted_key, key_hmac, salt, iv, date_created, time_created, action, key_type)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (self.current_user, key_name, encrypted_key, key_hmac, salt, iv_b64, current_date, current_time, 'Decrypt', key_type))
                    conn2.commit()
                    new_id = cursor2.lastrowid
                    conn2.close()
                    history_table.insert("", 0, values=(new_id, key_name, key_type, current_date, current_time, 'Decrypt'))
            self.password_prompt("Decrypt Key", perform_decryption)
        
        def delete_key():
            selected = history_table.selection()
            if not selected:
                messagebox.showerror("Error", "Please select a key to delete")
                return
            key_id = history_table.item(selected[0])['values'][0]

            def perform_deletion(pwd):
                if messagebox.askyesno("Confirm", "Are you sure you want to delete this key?"):
                    conn = self.get_db_connection()
                    cursor = conn.cursor()
                    cursor.execute("DELETE FROM quantum_keys WHERE id = ? AND username = ?", (key_id, self.current_user))
                    conn.commit()
                    conn.close()
                    history_table.delete(selected[0])
                    messagebox.showinfo("Success", "Key deleted successfully")
            self.password_prompt("Delete Key", perform_deletion)
            
        hybrid_frame = ttk.LabelFrame(hybrid_key_frame, text="Hybrid Key Generation")
        hybrid_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        quantum_visible = [False]
        kyber_visible = [False]
        hybrid_visible = [False]

        quantum_frame = ttk.LabelFrame(hybrid_frame, text="Quantum Key")
        quantum_frame.pack(fill=tk.X, padx=10, pady=10)
        quantum_display_frame = ttk.Frame(quantum_frame)
        quantum_display_frame.pack(fill=tk.X, padx=10, pady=5)
        quantum_key_text = scrolledtext.ScrolledText(quantum_display_frame, height=4, state=tk.DISABLED)
        quantum_key_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        quantum_view_button = ttk.Button(quantum_display_frame, text="View Key", width=10,
                                        command=lambda: toggle_key('quantum'))
        quantum_view_button.pack(side=tk.LEFT, padx=5)
        quantum_status_var = tk.StringVar(value="Not loaded")
        tk.Label(quantum_frame, textvariable=quantum_status_var).pack(anchor=tk.W, padx=10, pady=5)

        kyber_frame = ttk.LabelFrame(hybrid_frame, text="Kyber Key")
        kyber_frame.pack(fill=tk.X, padx=10, pady=10)
        kyber_display_frame = ttk.Frame(kyber_frame)
        kyber_display_frame.pack(fill=tk.X, padx=10, pady=5)
        kyber_key_text = scrolledtext.ScrolledText(kyber_display_frame, height=4, state=tk.DISABLED)
        kyber_key_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        kyber_view_button = ttk.Button(kyber_display_frame, text="View Key", width=10,
                                    command=lambda: toggle_key('kyber'))
        kyber_view_button.pack(side=tk.LEFT, padx=5)
        kyber_status_var = tk.StringVar(value="Not loaded")
        tk.Label(kyber_frame, textvariable=kyber_status_var).pack(anchor=tk.W, padx=10, pady=5)

        result_frame = ttk.LabelFrame(hybrid_frame, text="Hybrid Key Result")
        result_frame.pack(fill=tk.X, padx=10, pady=10)

        hybrid_status_var = tk.StringVar(value="Not loaded")
        tk.Label(result_frame, text="Hybrid Key Status:").pack(anchor=tk.W, padx=10, pady=(5,0))
        tk.Label(result_frame, textvariable=hybrid_status_var).pack(anchor=tk.W, padx=10, pady=(0,5))
        result_display_frame = ttk.Frame(result_frame)
        result_display_frame.pack(fill=tk.X, padx=10, pady=5)
        result_key_text = scrolledtext.ScrolledText(result_display_frame, height=4, state=tk.DISABLED)
        result_key_text.pack(side=tk.LEFT, fill=tk.X, expand=True)
        hybrid_view_button = ttk.Button(result_display_frame, text="View Key", width=10,
                                        command=lambda: toggle_key('hybrid'))
        hybrid_view_button.pack(side=tk.LEFT, padx=5)
        hybrid_name_frame = ttk.Frame(result_frame)
        hybrid_name_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(hybrid_name_frame, text="Save As:").pack(side=tk.LEFT, padx=5)
        hybrid_name_entry = tk.Entry(hybrid_name_frame, font=("Arial", 12))
        hybrid_name_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)
        hybrid_password_frame = ttk.Frame(result_frame)
        hybrid_password_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(hybrid_password_frame, text="Password:").pack(side=tk.LEFT, padx=5)
        hybrid_password_entry = tk.Entry(hybrid_password_frame, show="*", font=("Arial", 12))
        hybrid_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=5)

        def toggle_key(key_type):
            if key_type == 'quantum':
                if self.quantum_key is None:
                    return
                if quantum_visible[0]:
                    masked = '*' * len(self.quantum_key)
                    quantum_key_text.config(state=tk.NORMAL)
                    quantum_key_text.delete("1.0", tk.END)
                    quantum_key_text.insert(tk.END, masked)
                    quantum_key_text.config(state=tk.DISABLED)
                    quantum_view_button.config(text="View Key")
                    quantum_visible[0] = False
                else:
                    quantum_key_text.config(state=tk.NORMAL)
                    quantum_key_text.delete("1.0", tk.END)
                    quantum_key_text.insert(tk.END, self.quantum_key)
                    quantum_key_text.config(state=tk.DISABLED)
                    quantum_view_button.config(text="Hide Key")
                    quantum_visible[0] = True
            elif key_type == 'kyber':
                if self.kyber_key is None:
                    return
                if kyber_visible[0]:
                    masked = '*' * len(self.kyber_key)
                    kyber_key_text.config(state=tk.NORMAL)
                    kyber_key_text.delete("1.0", tk.END)
                    kyber_key_text.insert(tk.END, masked)
                    kyber_key_text.config(state=tk.DISABLED)
                    kyber_view_button.config(text="View Key")
                    kyber_visible[0] = False
                else:
                    kyber_key_text.config(state=tk.NORMAL)
                    kyber_key_text.delete("1.0", tk.END)
                    kyber_key_text.insert(tk.END, self.kyber_key)
                    kyber_key_text.config(state=tk.DISABLED)
                    kyber_view_button.config(text="Hide Key")
                    kyber_visible[0] = True
            elif key_type == 'hybrid':
                if not hasattr(self, 'hybrid_key') or self.hybrid_key is None:
                    return
                if hybrid_visible[0]:
                    masked = '*' * len(self.hybrid_key)
                    result_key_text.config(state=tk.NORMAL)
                    result_key_text.delete("1.0", tk.END)
                    result_key_text.insert(tk.END, masked)
                    result_key_text.config(state=tk.DISABLED)
                    hybrid_view_button.config(text="View Key")
                    hybrid_visible[0] = False
                else:
                    result_key_text.config(state=tk.NORMAL)
                    result_key_text.delete("1.0", tk.END)
                    result_key_text.insert(tk.END, self.hybrid_key)
                    result_key_text.config(state=tk.DISABLED)
                    hybrid_view_button.config(text="Hide Key")
                    hybrid_visible[0] = True

        def update_hybrid_key_displays():
            if self.quantum_key is not None:
                masked = '*' * len(self.quantum_key)
                quantum_key_text.config(state=tk.NORMAL)
                quantum_key_text.delete("1.0", tk.END)
                quantum_key_text.insert(tk.END, masked)
                quantum_key_text.config(state=tk.DISABLED)
                quantum_status_var.set("Loaded")
            else:
                quantum_key_text.config(state=tk.NORMAL)
                quantum_key_text.delete("1.0", tk.END)
                quantum_key_text.config(state=tk.DISABLED)
                quantum_status_var.set("Not loaded")
            if self.kyber_key is not None:
                masked = '*' * len(self.kyber_key)
                kyber_key_text.config(state=tk.NORMAL)
                kyber_key_text.delete("1.0", tk.END)
                kyber_key_text.insert(tk.END, masked)
                kyber_key_text.config(state=tk.DISABLED)
                kyber_status_var.set("Loaded")
            else:
                kyber_key_text.config(state=tk.NORMAL)
                kyber_key_text.delete("1.0", tk.END)
                kyber_key_text.config(state=tk.DISABLED)
                kyber_status_var.set("Not loaded")
            if hasattr(self, 'hybrid_key') and self.hybrid_key:
                masked = '*' * len(self.hybrid_key)
                result_key_text.config(state=tk.NORMAL)
                result_key_text.delete("1.0", tk.END)
                result_key_text.insert(tk.END, masked)
                result_key_text.config(state=tk.DISABLED)
                hybrid_status_var.set("Loaded")
            else:
                result_key_text.config(state=tk.NORMAL)
                result_key_text.delete("1.0", tk.END)
                result_key_text.config(state=tk.DISABLED)
                hybrid_status_var.set("Not loaded")
        update_hybrid_key_displays()

        def generate_hybrid_key():
            if not self.quantum_key or not self.kyber_key:
                messagebox.showerror("Error", "Both Quantum and Kyber keys are required")
                return
            try:
                combined = (self.quantum_key + self.kyber_key).encode('utf-8')

                salt = b'hybrid_key_salt'  

                time_cost = 3      
                memory_cost = 64 * 1024 
                parallelism = 2     
                hash_len = 64       

                derived_key = hash_secret_raw(
                    secret=combined,
                    salt=salt,
                    time_cost=time_cost,
                    memory_cost=memory_cost,
                    parallelism=parallelism,
                    hash_len=hash_len,
                    type=Type.ID
                )
                hybrid_result = derived_key.hex()

                self.hybrid_key = hybrid_result
                masked = '*' * len(hybrid_result)
                result_key_text.config(state=tk.NORMAL)
                result_key_text.delete("1.0", tk.END)
                result_key_text.insert(tk.END, masked)
                result_key_text.config(state=tk.DISABLED)
                hybrid_visible[0] = False
                hybrid_view_button.config(text="View Key")
                hybrid_status_var.set("Loaded")
                messagebox.showinfo("Success", "Hybrid Key Generated Successfully!")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate hybrid key: {str(e)}")
            
        def copy_hybrid_key():
            if hasattr(self, 'hybrid_key') and self.hybrid_key:
                self.kms_window.clipboard_clear()
                self.kms_window.clipboard_append(self.hybrid_key)
                messagebox.showinfo("Copied", "Hybrid Key copied to clipboard")
                self.kms_window.after(30000, lambda: self.kms_window.clipboard_clear())
            else:
                messagebox.showerror("Error", "No hybrid key to copy")
        
        def clear_all_hybrid_fields():
            self.quantum_key = None
            quantum_key_text.config(state=tk.NORMAL)
            quantum_key_text.delete("1.0", tk.END)
            quantum_key_text.config(state=tk.DISABLED)
            quantum_status_var.set("Not loaded")
            self.kyber_key = None
            kyber_key_text.config(state=tk.NORMAL)
            kyber_key_text.delete("1.0", tk.END)
            kyber_key_text.config(state=tk.DISABLED)
            kyber_status_var.set("Not loaded")
            self.hybrid_key = None
            result_key_text.config(state=tk.NORMAL)
            result_key_text.delete("1.0", tk.END)
            result_key_text.config(state=tk.DISABLED)
            hybrid_name_entry.delete(0, tk.END)
            hybrid_password_entry.delete(0, tk.END)
            hybrid_status_var.set("Not loaded")
            messagebox.showinfo("Cleared", "All hybrid key fields have been cleared")
            
        def save_hybrid_key():
            if not hasattr(self, 'hybrid_key') or not self.hybrid_key:
                messagebox.showerror("Error", "No hybrid key to save")
                return
            key_name = hybrid_name_entry.get().strip()
            pwd = hybrid_password_entry.get()
            if not key_name or not pwd:
                messagebox.showerror("Error", "Please enter key name and password")
                return
            result = self.encrypt_quantum_key(pwd, self.hybrid_key)
            if result:
                encrypted_key, key_hmac, salt, iv_b64 = result
                conn = self.get_db_connection()
                cursor = conn.cursor()
                current_date = datetime.now().strftime("%Y-%m-%d")
                current_time = datetime.now().strftime("%H:%M:%S")
                cursor.execute("""
                    INSERT INTO quantum_keys (username, key_name, encrypted_key, key_hmac, salt, iv, date_created, time_created, action, key_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (self.current_user, key_name, encrypted_key, key_hmac, salt, iv_b64,
                    current_date, current_time, 'Hybrid-Gen', 'hybrid'))
                new_id = cursor.lastrowid
                cursor.execute("""
                    INSERT INTO hybrid_keys (username, key_name, encrypted_key, key_hmac, salt, iv, date_created, time_created, quantum_key_id, kyber_key_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (self.current_user, key_name, encrypted_key, key_hmac, salt, iv_b64,
                    current_date, current_time, None, None))
                conn.commit()
                conn.close()
                messagebox.showinfo("Success", "Hybrid Key saved successfully")
                notebook.select(key_management_frame)

        button_frame = ttk.Frame(key_management_frame)
        button_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(button_frame, text="Encrypt Key", command=encrypt_key, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt Key", command=decrypt_key, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Delete Key", command=delete_key, width=15).pack(side=tk.LEFT, padx=5)
        hybrid_button_frame = ttk.Frame(hybrid_frame)
        hybrid_button_frame.pack(fill=tk.X, padx=10, pady=10)
        ttk.Button(hybrid_button_frame, text="Generate Hybrid Key", command=generate_hybrid_key, width=20).pack(side=tk.LEFT, padx=5)
        ttk.Button(hybrid_button_frame, text="Copy Hybrid Key", command=copy_hybrid_key, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(hybrid_button_frame, text="Save Hybrid Key", command=save_hybrid_key, width=15).pack(side=tk.LEFT, padx=5)
        ttk.Button(hybrid_button_frame, text="Clear All", command=clear_all_hybrid_fields, width=15).pack(side=tk.LEFT, padx=5)

        load_user_keys()

    def start_application(self):
        self.root = tk.Tk()
        self.root.title("Key Management System")
        self.center_window(self.root, 800, 600)
        main_frame = ttk.Frame(self.root, padding=20)
        main_frame.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(main_frame, text="Key Management System", font=("Helvetica", 24, "bold")).pack(pady=(0, 20))
        tk.Label(main_frame, text="Secure Storage for Quantum and Post-Quantum Keys", font=("Helvetica", 14)).pack(pady=(0, 40))
        ttk.Button(main_frame, text="Login", command=self.login, width=25).pack(pady=10, ipadx=50, ipady=10)
        ttk.Button(main_frame, text="Register", command=self.register, width=25).pack(pady=10, ipadx=50, ipady=10)
        self.root.mainloop()

if __name__ == "__main__":
    kms = QuantumKeyManagementSystem()
    kms.start_application()
