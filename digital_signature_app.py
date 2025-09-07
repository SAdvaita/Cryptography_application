import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
from cryptography.hazmat.primitives import hashes # type: ignore
from cryptography.hazmat.primitives.asymmetric import rsa, padding # type: ignore
from cryptography.hazmat.primitives import serialization # type: ignore
from cryptography.exceptions import InvalidSignature # type: ignore

# --- Core Cryptographic Functions ---

def generate_keys():
    """Generates a new RSA private and public key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()
    return private_key, public_key

def sign_message(private_key, message):
    """Signs a message using the private key."""
    # The message must be converted to bytes
    message_bytes = message.encode('utf-8')
    
    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(public_key, message, signature):
    """Verifies a signature using the public key. Returns True if valid, False otherwise."""
    message_bytes = message.encode('utf-8')
    try:
        public_key.verify(
            signature,
            message_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
    except Exception as e:
        print(f"An error occurred during verification: {e}")
        return False

# --- Main Application Class ---

class SignatureApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Digital Signature Verifier")
        self.geometry("800x650")
        self.configure(bg="#f0f0f0")

        self.private_key = None
        self.public_key = None

        self._create_widgets()

    def _create_widgets(self):
        main_frame = tk.Frame(self, bg="#f0f0f0", padx=10, pady=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Key Generation Frame ---
        key_frame = tk.LabelFrame(main_frame, text="1. Key Management", padx=10, pady=10, bg="#e0e8f0", font=("Arial", 12, "bold"))
        key_frame.pack(fill=tk.X, pady=10)
        
        tk.Button(key_frame, text="Generate New RSA Key Pair", command=self.gui_generate_keys, font=("Arial", 10, "bold"), bg="#4a90e2", fg="white").pack(side=tk.LEFT, padx=5)
        tk.Button(key_frame, text="Save Public Key", command=self.gui_save_public_key, bg="#50c878").pack(side=tk.LEFT, padx=5)
        tk.Button(key_frame, text="Save Private Key", command=self.gui_save_private_key, bg="#f5a623").pack(side=tk.LEFT, padx=5)

        # --- Signing Frame ---
        sign_frame = tk.LabelFrame(main_frame, text="2. Sign a Document (The Signer)", padx=10, pady=10, bg="#e0f0e8", font=("Arial", 12, "bold"))
        sign_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        tk.Label(sign_frame, text="Enter message to sign:", bg="#e0f0e8", font=("Arial", 10)).pack(anchor="w")
        self.sign_text = scrolledtext.ScrolledText(sign_frame, height=8, width=80, wrap=tk.WORD)
        self.sign_text.pack(pady=5, fill=tk.BOTH, expand=True)
        
        sign_button_frame = tk.Frame(sign_frame, bg="#e0f0e8")
        sign_button_frame.pack(fill=tk.X, pady=5)
        tk.Button(sign_button_frame, text="Load Private Key to Sign", command=self.gui_load_private_key_for_signing, bg="#f5a623").pack(side=tk.LEFT, padx=5)
        tk.Button(sign_button_frame, text="Sign Message & Save Signature", command=self.gui_sign_message, font=("Arial", 10, "bold"), bg="#d0021b", fg="white").pack(side=tk.LEFT, padx=5)

        # --- Verification Frame ---
        verify_frame = tk.LabelFrame(main_frame, text="3. Verify a Document (The Receiver)", padx=10, pady=10, bg="#f0e8e0", font=("Arial", 12, "bold"))
        verify_frame.pack(fill=tk.BOTH, expand=True, pady=10)

        tk.Label(verify_frame, text="Enter the original message to verify:", bg="#f0e8e0", font=("Arial", 10)).pack(anchor="w")
        self.verify_text = scrolledtext.ScrolledText(verify_frame, height=8, width=80, wrap=tk.WORD)
        self.verify_text.pack(pady=5, fill=tk.BOTH, expand=True)

        verify_button_frame = tk.Frame(verify_frame, bg="#f0e8e0")
        verify_button_frame.pack(fill=tk.X, pady=5)
        tk.Button(verify_button_frame, text="Load Sender's Public Key", command=self.gui_load_public_key_for_verification, bg="#50c878").pack(side=tk.LEFT, padx=5)
        tk.Button(verify_button_frame, text="Load Signature File", command=self.gui_load_signature, bg="#8b572a").pack(side=tk.LEFT, padx=5)
        tk.Button(verify_button_frame, text="VERIFY SIGNATURE", command=self.gui_verify_signature, font=("Arial", 10, "bold"), bg="#4a90e2", fg="white").pack(side=tk.LEFT, padx=5)

    def gui_generate_keys(self):
        self.private_key, self.public_key = generate_keys()
        messagebox.showinfo("Success", "New RSA key pair generated successfully!\n\nDon't forget to save them.")

    def _save_key(self, key_data, title, file_ext, file_types):
        if not key_data:
            messagebox.showerror("Error", "No key to save. Please generate or load a key first.")
            return
        filepath = filedialog.asksaveasfilename(
            title=title,
            defaultextension=file_ext,
            filetypes=file_types
        )
        if filepath:
            with open(filepath, "wb") as f:
                f.write(key_data)
            messagebox.showinfo("Success", f"Key saved to {filepath}")

    def gui_save_public_key(self):
        pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ) if self.public_key else None
        self._save_key(pem, "Save Public Key", ".pem", [("PEM files", "*.pem")])

    def gui_save_private_key(self):
        pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ) if self.private_key else None
        self._save_key(pem, "Save Private Key", ".pem", [("PEM files", "*.pem")])

    def gui_load_private_key_for_signing(self):
        filepath = filedialog.askopenfilename(title="Select Private Key File", filetypes=[("PEM files", "*.pem")])
        if filepath:
            with open(filepath, "rb") as f:
                self.private_key = serialization.load_pem_private_key(f.read(), password=None)
            messagebox.showinfo("Success", "Private key loaded successfully.")

    def gui_sign_message(self):
        if not self.private_key:
            messagebox.showerror("Error", "No private key loaded. Please generate or load a private key first.")
            return
        
        message = self.sign_text.get("1.0", tk.END).strip()
        if not message:
            messagebox.showerror("Error", "Cannot sign an empty message.")
            return

        signature = sign_message(self.private_key, message)
        
        filepath = filedialog.asksaveasfilename(title="Save Signature File", defaultextension=".sig", filetypes=[("Signature files", "*.sig")])
        if filepath:
            with open(filepath, "wb") as f:
                f.write(signature)
            messagebox.showinfo("Success", f"Message signed and signature saved to {filepath}")

    def gui_load_public_key_for_verification(self):
        filepath = filedialog.askopenfilename(title="Select Public Key File", filetypes=[("PEM files", "*.pem")])
        if filepath:
            with open(filepath, "rb") as f:
                self.verify_public_key = serialization.load_pem_public_key(f.read())
            messagebox.showinfo("Success", "Public key loaded for verification.")
    
    def gui_load_signature(self):
        filepath = filedialog.askopenfilename(title="Select Signature File", filetypes=[("Signature files", "*.sig")])
        if filepath:
            with open(filepath, "rb") as f:
                self.signature_to_verify = f.read()
            messagebox.showinfo("Success", "Signature file loaded.")

    def gui_verify_signature(self):
        message = self.verify_text.get("1.0", tk.END).strip()
        if not hasattr(self, 'verify_public_key') or not self.verify_public_key:
            messagebox.showerror("Error", "Please load the sender's public key first.")
            return
        if not hasattr(self, 'signature_to_verify') or not self.signature_to_verify:
            messagebox.showerror("Error", "Please load the signature file first.")
            return
        if not message:
            messagebox.showerror("Error", "Please enter the message to verify.")
            return

        is_valid = verify_signature(self.verify_public_key, message, self.signature_to_verify)

        if is_valid:
            messagebox.showinfo("Verification Result", "✅ SIGNATURE IS VALID\n\nThe message is authentic and has not been tampered with.")
        else:
            messagebox.showerror("Verification Result", "❌ INVALID SIGNATURE\n\nThe message may be fraudulent or has been altered!")


if __name__ == "__main__":
    app = SignatureApp()
    app.mainloop()
