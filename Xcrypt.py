import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import os
import binascii
import string
import random

class CryptoApp:
    def __init__(self, window):
        self.window = window
        self.window.title("Xcrypt 🔐 - Advanced Encryption Tool")
        self.window.geometry("800x700")
        self.window.configure(bg='#2c3e50')
        
        design = ttk.Style()
        design.theme_use('clam')
        design.configure('Custom.TFrame', background='#34495e')
        design.configure('Custom.TLabel', background='#34495e', foreground='white', font=('Arial', 10))
        design.configure('Custom.TButton', font=('Arial', 9, 'bold'))
        
        self.setup_interface()
        
    def setup_interface(self):
        def get_font(preferred_fonts, size=11, weight="normal"):
            from tkinter import font
            available = font.families()
            for f in preferred_fonts:
                if f in available:
                    return (f, size, weight)
            return ("Arial", size, weight)

        header_font = get_font(["Segoe UI", "Poppins", "Helvetica"], 26, "bold")
        label_font = get_font(["Inter", "Segoe UI", "Calibri"], 11)
        entry_font = get_font(["Inter", "Segoe UI", "Arial"], 11)
        text_font = get_font(["Fira Code", "Consolas", "Courier New"], 11)
    
        self.window.configure(bg="#1e1e2f")

        header = tk.Label(self.window, text="Xcrypt 🔐", font=header_font,
                          fg='#f1c40f', bg='#1e1e2f')
        header.pack(pady=(20, 10))

        container = ttk.Frame(self.window, style='Custom.TFrame')
        container.pack(fill='both', expand=True, padx=25, pady=10)

        selector_area = ttk.Frame(container, style='Custom.TFrame')
        selector_area.pack(fill='x', pady=(0, 15))

        ttk.Label(selector_area, text="Encryption Method:", font=label_font, style='Custom.TLabel').pack(side='left', padx=(5, 10))

        self.cipher_choice = tk.StringVar(value="caesar")
        dropdown_menu = ttk.Combobox(selector_area, textvariable=self.cipher_choice,
                                     values=[
                                         "caesar", "vigenere", "base64", "rot13", "atbash",
                                         "aes", "rsa_sim", "xor", "morse", "binary"
                                     ],
                                     font=entry_font, state='readonly', width=22)
        dropdown_menu.pack(side='left')
        dropdown_menu.bind('<<ComboboxSelected>>', self.update_key_field)

        text_input_area = ttk.Frame(container, style='Custom.TFrame')
        text_input_area.pack(fill='both', expand=True, pady=10)

        ttk.Label(text_input_area, text="Input Text:", font=label_font, style='Custom.TLabel').pack(anchor='w', padx=5)
        self.user_input = scrolledtext.ScrolledText(text_input_area, height=7, font=text_font,
                                                    bg="#2f2f3f", fg="white", insertbackground="white",
                                                    relief='flat', bd=1)
        self.user_input.pack(fill='both', expand=True, pady=5)

        key_input_area = ttk.Frame(container, style='Custom.TFrame')
        key_input_area.pack(fill='x', pady=(0, 10))

        self.key_description = ttk.Label(key_input_area, text="Key / Shift:", font=label_font, style='Custom.TLabel')
        self.key_description.pack(side='left', padx=5)

        self.secret_key = tk.Entry(key_input_area, font=entry_font, width=25,
                                   bg='#2f2f3f', fg='white', insertbackground='white',
                                   relief='flat', bd=1)
        self.secret_key.pack(side='left', padx=10)

        self.create_key_button = ttk.Button(key_input_area, text="Generate Key",
                                            command=self.create_random_key, style='Custom.TButton')
        self.create_key_button.pack(side='left', padx=5)

        action_buttons = ttk.Frame(container, style='Custom.TFrame')
        action_buttons.pack(fill='x', pady=15)
    
        buttons = [
            ("🔒 Encrypt", self.encrypt_message),
            ("🔓 Decrypt", self.decrypt_message),
            ("🗑️ Clear", self.reset_fields),
            ("📋 Copy", self.copy_output),
            ("📁 Load File", self.import_file),
            ("💾 Save", self.export_result)
        ]

        for text, cmd in buttons:
            ttk.Button(action_buttons, text=text, command=cmd, style='Custom.TButton') \
                .pack(side='left', padx=6, ipadx=4, ipady=2)

        result_area = ttk.Frame(container, style='Custom.TFrame')
        result_area.pack(fill='both', expand=True, pady=10)

        ttk.Label(result_area, text="Output:", font=label_font, style='Custom.TLabel').pack(anchor='w', padx=5)
        self.display_output = scrolledtext.ScrolledText(result_area, height=7, font=text_font,
                                                        bg="#2f2f3f", fg="white", insertbackground="white",
                                                        relief='flat', bd=1)
        self.display_output.pack(fill='both', expand=True, pady=5)

        self.app_status = tk.StringVar(value="Ready")
        bottom_bar = tk.Label(self.window, textvariable=self.app_status, relief='flat',
                          anchor='w', bg='#16161e', fg='white', font=label_font)
        bottom_bar.pack(side='bottom', fill='x', pady=(5, 0))

        self.update_key_field()


    
    def update_key_field(self, event=None):
        selected_cipher = self.cipher_choice.get()
        if selected_cipher in ['base64', 'rot13', 'atbash', 'morse', 'binary']:
            self.key_description.config(text="No key needed")
            self.secret_key.config(state='disabled')
            self.create_key_button.config(state='disabled')
        elif selected_cipher == 'caesar':
            self.key_description.config(text="Shift (0-25):")
            self.secret_key.config(state='normal')
            self.create_key_button.config(state='disabled')
        elif selected_cipher in ['vigenere', 'xor']:
            self.key_description.config(text="Key:")
            self.secret_key.config(state='normal')
            self.create_key_button.config(state='disabled')
        elif selected_cipher == 'aes':
            self.key_description.config(text="Password:")
            self.secret_key.config(state='normal')
            self.create_key_button.config(state='normal')
        elif selected_cipher == 'rsa_sim':
            self.key_description.config(text="Key (p,q):")
            self.secret_key.config(state='normal')
            self.create_key_button.config(state='normal')
    
    def create_random_key(self):
        current_method = self.cipher_choice.get()
        if current_method == 'aes':
            password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
            self.secret_key.delete(0, tk.END)
            self.secret_key.insert(0, password)
        elif current_method == 'rsa_sim':
            prime_numbers = [17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97]
            first_prime, second_prime = random.sample(prime_numbers, 2)
            self.secret_key.delete(0, tk.END)
            self.secret_key.insert(0, f"{first_prime},{second_prime}")
    
    def encrypt_message(self):
        try:
            message = self.user_input.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter text to encrypt!")
                return
            
            cipher_type = self.cipher_choice.get()
            user_key = self.secret_key.get().strip()
            
            encrypted_result = self.run_encryption(message, cipher_type, user_key)
            
            self.display_output.delete("1.0", tk.END)
            self.display_output.insert("1.0", encrypted_result)
            self.app_status.set(f"Encrypted using {cipher_type.upper()}")
            
        except Exception as error:
            messagebox.showerror("Error", f"Encryption failed: {str(error)}")
            self.app_status.set("Encryption failed")
    
    def decrypt_message(self):
        try:
            encrypted_text = self.user_input.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showwarning("Warning", "Please enter text to decrypt!")
                return
            
            cipher_type = self.cipher_choice.get()
            user_key = self.secret_key.get().strip()
            
            decrypted_result = self.run_decryption(encrypted_text, cipher_type, user_key)
            
            self.display_output.delete("1.0", tk.END)
            self.display_output.insert("1.0", decrypted_result)
            self.app_status.set(f"Decrypted using {cipher_type.upper()}")
            
        except Exception as error:
            messagebox.showerror("Error", f"Decryption failed: {str(error)}")
            self.app_status.set("Decryption failed")
    
    def run_encryption(self, plaintext, cipher_method, key_value):
        if cipher_method == "caesar":
            shift_amount = int(key_value) if key_value.isdigit() else 3
            return self.caesar_encode(plaintext, shift_amount)
        elif cipher_method == "vigenere":
            if not key_value:
                raise ValueError("Vigenère cipher requires a key")
            return self.vigenere_encode(plaintext, key_value)
        elif cipher_method == "base64":
            return base64.b64encode(plaintext.encode()).decode()
        elif cipher_method == "rot13":
            return plaintext.encode('rot13')
        elif cipher_method == "atbash":
            return self.atbash_transform(plaintext)
        elif cipher_method == "aes":
            if not key_value:
                raise ValueError("AES encryption requires a password")
            return self.aes_encode(plaintext, key_value)
        elif cipher_method == "rsa_sim":
            if not key_value:
                raise ValueError("RSA requires p,q values")
            return self.rsa_encode(plaintext, key_value)
        elif cipher_method == "xor":
            if not key_value:
                raise ValueError("XOR cipher requires a key")
            return self.xor_transform(plaintext, key_value)
        elif cipher_method == "morse":
            return self.text_to_morse(plaintext)
        elif cipher_method == "binary":
            return self.text_to_binary(plaintext)
    
    def run_decryption(self, ciphertext, cipher_method, key_value):
        if cipher_method == "caesar":
            shift_amount = int(key_value) if key_value.isdigit() else 3
            return self.caesar_decode(ciphertext, shift_amount)
        elif cipher_method == "vigenere":
            if not key_value:
                raise ValueError("Vigenère cipher requires a key")
            return self.vigenere_decode(ciphertext, key_value)
        elif cipher_method == "base64":
            return base64.b64decode(ciphertext.encode()).decode()
        elif cipher_method == "rot13":
            return ciphertext.encode('rot13')
        elif cipher_method == "atbash":
            return self.atbash_transform(ciphertext)
        elif cipher_method == "aes":
            if not key_value:
                raise ValueError("AES decryption requires a password")
            return self.aes_decode(ciphertext, key_value)
        elif cipher_method == "rsa_sim":
            if not key_value:
                raise ValueError("RSA requires p,q values")
            return self.rsa_decode(ciphertext, key_value)
        elif cipher_method == "xor":
            if not key_value:
                raise ValueError("XOR cipher requires a key")
            return self.xor_transform(ciphertext, key_value)
        elif cipher_method == "morse":
            return self.morse_to_text(ciphertext)
        elif cipher_method == "binary":
            return self.binary_to_text(ciphertext)
    
    def caesar_encode(self, text, shift_value):
        output = ""
        for character in text:
            if character.isalpha():
                base_value = ord('A') if character.isupper() else ord('a')
                output += chr((ord(character) - base_value + shift_value) % 26 + base_value)
            else:
                output += character
        return output
    
    def caesar_decode(self, text, shift_value):
        return self.caesar_encode(text, -shift_value)
    
    def vigenere_encode(self, plaintext, keyword):
        keyword = keyword.upper()
        output = ""
        key_position = 0
        for character in plaintext:
            if character.isalpha():
                shift_value = ord(keyword[key_position % len(keyword)]) - ord('A')
                if character.isupper():
                    output += chr((ord(character) - ord('A') + shift_value) % 26 + ord('A'))
                else:
                    output += chr((ord(character) - ord('a') + shift_value) % 26 + ord('a'))
                key_position += 1
            else:
                output += character
        return output
    
    def vigenere_decode(self, ciphertext, keyword):
        keyword = keyword.upper()
        output = ""
        key_position = 0
        for character in ciphertext:
            if character.isalpha():
                shift_value = ord(keyword[key_position % len(keyword)]) - ord('A')
                if character.isupper():
                    output += chr((ord(character) - ord('A') - shift_value + 26) % 26 + ord('A'))
                else:
                    output += chr((ord(character) - ord('a') - shift_value + 26) % 26 + ord('a'))
                key_position += 1
            else:
                output += character
        return output
    
    def atbash_transform(self, text):
        output = ""
        for character in text:
            if character.isalpha():
                if character.isupper():
                    output += chr(ord('Z') - (ord(character) - ord('A')))
                else:
                    output += chr(ord('z') - (ord(character) - ord('a')))
            else:
                output += character
        return output
    
    def aes_encode(self, plaintext, password):
        password_bytes = password.encode()
        random_salt = os.urandom(16)
        key_derivation = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=random_salt, iterations=100000)
        derived_key = base64.urlsafe_b64encode(key_derivation.derive(password_bytes))
        
        cipher = Fernet(derived_key)
        encrypted_data = cipher.encrypt(plaintext.encode())
        
        return base64.b64encode(random_salt + encrypted_data).decode()
    
    def aes_decode(self, ciphertext, password):
        combined_data = base64.b64decode(ciphertext.encode())
        random_salt = combined_data[:16]
        encrypted_data = combined_data[16:]
        
        password_bytes = password.encode()
        key_derivation = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=random_salt, iterations=100000)
        derived_key = base64.urlsafe_b64encode(key_derivation.derive(password_bytes))
        
        cipher = Fernet(derived_key)
        decrypted_data = cipher.decrypt(encrypted_data)
        return decrypted_data.decode()
    
    def rsa_encode(self, plaintext, key_string):
        try:
            first_prime, second_prime = map(int, key_string.split(','))
            modulus = first_prime * second_prime
            totient = (first_prime - 1) * (second_prime - 1)
            public_exp = 65537
            
            private_exp = self.find_mod_inverse(public_exp, totient)
            
            encrypted_chars = []
            for character in plaintext:
                char_value = ord(character)
                if char_value >= modulus:
                    raise ValueError(f"Character '{character}' too large for key size")
                encrypted_value = pow(char_value, public_exp, modulus)
                encrypted_chars.append(str(encrypted_value))
            
            return f"n={modulus},d={private_exp};" + ",".join(encrypted_chars)
        except Exception as error:
            raise ValueError(f"RSA encryption failed: {str(error)}")
    
    def rsa_decode(self, ciphertext, key_string):
        try:
            key_part, data_part = ciphertext.split(';')
            modulus = int(key_part.split(',')[0].split('=')[1])
            private_exp = int(key_part.split(',')[1].split('=')[1])
            
            encrypted_values = list(map(int, data_part.split(',')))
            
            decrypted_text = ""
            for encrypted_value in encrypted_values:
                char_value = pow(encrypted_value, private_exp, modulus)
                decrypted_text += chr(char_value)
            
            return decrypted_text
        except Exception as error:
            raise ValueError(f"RSA decryption failed: {str(error)}")
    
    def find_mod_inverse(self, num, mod):
        if mod == 1:
            return 0
        original_mod, x0, x1 = mod, 0, 1
        while num > 1:
            quotient = num // mod
            mod, num = num % mod, mod
            x0, x1 = x1 - quotient * x0, x0
        return x1 + original_mod if x1 < 0 else x1
    
    def xor_transform(self, text, key):
        output = ""
        for position, character in enumerate(text):
            output += chr(ord(character) ^ ord(key[position % len(key)]))
        return output
    
    def text_to_morse(self, text):
        morse_table = {
            'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
            'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
            'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
            'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
            'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
            '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
            '8': '---..', '9': '----.', ' ': '/'
        }
        return ' '.join(morse_table.get(char.upper(), char) for char in text)
    
    def morse_to_text(self, morse_text):
        reverse_morse = {
            '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
            '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
            '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
            '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
            '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
            '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
            '---..': '8', '----.': '9', '/': ' '
        }
        return ''.join(reverse_morse.get(code, code) for code in morse_text.split())
    
    def text_to_binary(self, text):
        return ' '.join(format(ord(char), '08b') for char in text)
    
    def binary_to_text(self, binary_text):
        binary_values = binary_text.split()
        return ''.join(chr(int(code, 2)) for code in binary_values if code)
    
    def reset_fields(self):
        self.user_input.delete("1.0", tk.END)
        self.display_output.delete("1.0", tk.END)
        self.secret_key.delete(0, tk.END)
        self.app_status.set("Cleared")
    
    def copy_output(self):
        output_text = self.display_output.get("1.0", tk.END).strip()
        if output_text:
            self.window.clipboard_clear()
            self.window.clipboard_append(output_text)
            self.app_status.set("Copied to clipboard")
        else:
            messagebox.showwarning("Warning", "No output to copy!")
    
    def import_file(self):
        file_location = filedialog.askopenfilename(
            title="Select file to load",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if file_location:
            try:
                with open(file_location, 'r', encoding='utf-8') as file:
                    file_content = file.read()
                    self.user_input.delete("1.0", tk.END)
                    self.user_input.insert("1.0", file_content)
                    self.app_status.set(f"Loaded: {os.path.basename(file_location)}")
            except Exception as error:
                messagebox.showerror("Error", f"Failed to load file: {str(error)}")
    
    def export_result(self):
        output_text = self.display_output.get("1.0", tk.END).strip()
        if not output_text:
            messagebox.showwarning("Warning", "No output to save!")
            return
        
        save_location = filedialog.asksaveasfilename(
            title="Save result",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if save_location:
            try:
                with open(save_location, 'w', encoding='utf-8') as file:
                    file.write(output_text)
                    self.app_status.set(f"Saved: {os.path.basename(save_location)}")
            except Exception as error:
                messagebox.showerror("Error", f"Failed to save file: {str(error)}")

def main():
    window = tk.Tk()
    crypto_app = CryptoApp(window)
    window.mainloop()

if __name__ == "__main__":
    main()
