import tkinter as tk
from tkinter import ttk, messagebox
import string
import random
import json
import os
from cryptography.fernet import Fernet
import base64
import hashlib
import pyperclip

class PasswordManager:
    def __init__(self):
        self.key_file = "key.key"
        self.passwords_file = "passwords.enc"
        self.master_password_hash_file = "master.key"
        self.fernet = None
        self.passwords = {}
        
    def initialize(self, master_password):
        """Initialize the password manager with a master password"""
        if not os.path.exists(self.master_password_hash_file):
            # First time setup
            self.save_master_password(master_password)
            key = Fernet.generate_key()
            with open(self.key_file, "wb") as f:
                f.write(key)
            self.fernet = Fernet(key)
            self.save_passwords()
        else:
            # Verify master password
            if not self.verify_master_password(master_password):
                raise ValueError("Incorrect master password")
            with open(self.key_file, "rb") as f:
                key = f.read()
            self.fernet = Fernet(key)
            self.load_passwords()

    def save_master_password(self, password):
        """Save the hashed master password"""
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        with open(self.master_password_hash_file, "w") as f:
            f.write(password_hash)

    def verify_master_password(self, password):
        """Verify if the provided master password is correct"""
        with open(self.master_password_hash_file, "r") as f:
            stored_hash = f.read().strip()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        return stored_hash == password_hash

    def generate_password(self, length=12, use_uppercase=True, use_lowercase=True,
                         use_numbers=True, use_special=True):
        """Generate a random password with specified requirements"""
        characters = ""
        if use_uppercase:
            characters += string.ascii_uppercase
        if use_lowercase:
            characters += string.ascii_lowercase
        if use_numbers:
            characters += string.digits
        if use_special:
            characters += string.punctuation

        if not characters:
            raise ValueError("At least one character type must be selected")

        password = ''.join(random.choice(characters) for _ in range(length))
        return password

    def add_password(self, service, username, password):
        """Add or update a password entry"""
        self.passwords[service] = {
            'username': username,
            'password': password
        }
        self.save_passwords()

    def get_password(self, service):
        """Retrieve a password entry"""
        return self.passwords.get(service)

    def delete_password(self, service):
        """Delete a password entry"""
        if service in self.passwords:
            del self.passwords[service]
            self.save_passwords()
            return True
        return False

    def save_passwords(self):
        """Save passwords to encrypted file"""
        data = json.dumps(self.passwords)
        encrypted_data = self.fernet.encrypt(data.encode())
        with open(self.passwords_file, "wb") as f:
            f.write(encrypted_data)

    def load_passwords(self):
        """Load passwords from encrypted file"""
        if os.path.exists(self.passwords_file):
            with open(self.passwords_file, "rb") as f:
                encrypted_data = f.read()
            data = self.fernet.decrypt(encrypted_data)
            self.passwords = json.loads(data)
        else:
            self.passwords = {}

class PasswordManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Password Manager")
        self.root.geometry("600x400")
        
        # Get master password first
        if not self.get_master_password():
            self.root.destroy()
            return
            
        self.create_widgets()
        self.current_tab = None
        self.show_generate_tab()

    def get_master_password(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Master Password")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()

        tk.Label(dialog, text="Enter master password:").pack(pady=10)
        password_var = tk.StringVar()
        entry = tk.Entry(dialog, show="*", textvariable=password_var)
        entry.pack(pady=5)

        result = [False]

        def on_ok():
            password = password_var.get()
            if password:
                try:
                    self.password_manager = PasswordManager()
                    self.password_manager.initialize(password)
                    result[0] = True
                    dialog.destroy()
                except ValueError as e:
                    messagebox.showerror("Error", str(e))
            else:
                messagebox.showerror("Error", "Password is required!")

        def on_cancel():
            dialog.destroy()

        tk.Button(dialog, text="OK", command=on_ok).pack(side=tk.LEFT, padx=20, pady=20)
        tk.Button(dialog, text="Cancel", command=on_cancel).pack(side=tk.RIGHT, padx=20, pady=20)

        dialog.wait_window()
        return result[0]

    def create_widgets(self):
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)

        # Generate Password Tab
        self.generate_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.generate_frame, text='Generate Password')

        # Store Password Tab
        self.store_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.store_frame, text='Store Password')

        # View Passwords Tab
        self.view_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.view_frame, text='View Passwords')

        self.setup_generate_tab()
        self.setup_store_tab()
        self.setup_view_tab()

    def setup_generate_tab(self):
        # Password Length
        tk.Label(self.generate_frame, text="Password Length:").pack(pady=5)
        self.length_var = tk.StringVar(value="12")
        tk.Entry(self.generate_frame, textvariable=self.length_var, width=5).pack()

        # Checkboxes
        self.uppercase_var = tk.BooleanVar(value=True)
        self.lowercase_var = tk.BooleanVar(value=True)
        self.numbers_var = tk.BooleanVar(value=True)
        self.special_var = tk.BooleanVar(value=True)

        tk.Checkbutton(self.generate_frame, text="Uppercase", variable=self.uppercase_var).pack()
        tk.Checkbutton(self.generate_frame, text="Lowercase", variable=self.lowercase_var).pack()
        tk.Checkbutton(self.generate_frame, text="Numbers", variable=self.numbers_var).pack()
        tk.Checkbutton(self.generate_frame, text="Special Characters", variable=self.special_var).pack()

        # Generated Password
        self.generated_password_var = tk.StringVar()
        tk.Entry(self.generate_frame, textvariable=self.generated_password_var, width=30).pack(pady=10)

        # Buttons
        tk.Button(self.generate_frame, text="Generate", command=self.generate_password).pack(pady=5)
        tk.Button(self.generate_frame, text="Copy", command=self.copy_generated).pack(pady=5)

    def setup_store_tab(self):
        # Service
        tk.Label(self.store_frame, text="Service:").pack(pady=5)
        self.service_var = tk.StringVar()
        tk.Entry(self.store_frame, textvariable=self.service_var).pack()

        # Username
        tk.Label(self.store_frame, text="Username:").pack(pady=5)
        self.username_var = tk.StringVar()
        tk.Entry(self.store_frame, textvariable=self.username_var).pack()

        # Password
        tk.Label(self.store_frame, text="Password:").pack(pady=5)
        self.password_var = tk.StringVar()
        tk.Entry(self.store_frame, textvariable=self.password_var, show="*").pack()

        # Buttons
        tk.Button(self.store_frame, text="Save", command=self.save_password).pack(pady=10)
        tk.Button(self.store_frame, text="Clear", command=self.clear_store_fields).pack()

    def setup_view_tab(self):
        # Listbox for passwords
        self.passwords_listbox = tk.Listbox(self.view_frame, width=40, height=10)
        self.passwords_listbox.pack(pady=10)

        # Buttons
        tk.Button(self.view_frame, text="Refresh", command=self.refresh_passwords).pack(pady=5)
        tk.Button(self.view_frame, text="Delete", command=self.delete_password).pack(pady=5)
        tk.Button(self.view_frame, text="Copy Password", command=self.copy_selected).pack(pady=5)

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            password = self.password_manager.generate_password(
                length=length,
                use_uppercase=self.uppercase_var.get(),
                use_lowercase=self.lowercase_var.get(),
                use_numbers=self.numbers_var.get(),
                use_special=self.special_var.get()
            )
            self.generated_password_var.set(password)
        except ValueError as e:
            messagebox.showerror("Error", str(e))

    def copy_generated(self):
        password = self.generated_password_var.get()
        if password:
            pyperclip.copy(password)
            messagebox.showinfo("Success", "Password copied to clipboard!")

    def save_password(self):
        service = self.service_var.get()
        username = self.username_var.get()
        password = self.password_var.get()

        if service and username and password:
            self.password_manager.add_password(service, username, password)
            messagebox.showinfo("Success", "Password saved successfully!")
            self.clear_store_fields()
        else:
            messagebox.showerror("Error", "Please fill in all fields!")

    def clear_store_fields(self):
        self.service_var.set("")
        self.username_var.set("")
        self.password_var.set("")

    def refresh_passwords(self):
        self.passwords_listbox.delete(0, tk.END)
        for service, details in self.password_manager.passwords.items():
            self.passwords_listbox.insert(tk.END, f"{service}: {details['username']}")

    def delete_password(self):
        selection = self.passwords_listbox.curselection()
        if selection:
            service = self.passwords_listbox.get(selection[0]).split(':')[0]
            if self.password_manager.delete_password(service):
                messagebox.showinfo("Success", f"Password for {service} deleted!")
                self.refresh_passwords()

    def copy_selected(self):
        selection = self.passwords_listbox.curselection()
        if selection:
            service = self.passwords_listbox.get(selection[0]).split(':')[0]
            password_entry = self.password_manager.get_password(service)
            if password_entry:
                pyperclip.copy(password_entry['password'])
                messagebox.showinfo("Success", "Password copied to clipboard!")

    def show_generate_tab(self):
        self.notebook.select(0)

def main():
    root = tk.Tk()
    app = PasswordManagerGUI(root)
    root.mainloop()

if __name__ == '__main__':
    main() 