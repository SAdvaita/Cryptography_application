🛡️ Digital Signature Verifier ✍️
A user-friendly desktop application built with Python that demystifies the process of creating and verifying digital signatures using RSA cryptography.

This tool provides a hands-on way to understand how modern cryptography secures our digital world by ensuring data authenticity and integrity.

🤔 Why are Digital Signatures Important?
In the real world, a handwritten signature proves that you've seen and approved a document. A digital signature does the same for digital files, but with much stronger security. It provides:

Authenticity: Proof that the message was created by a known sender.

Integrity: Proof that the message has not been altered in any way since it was signed.

Non-repudiation: The creator cannot deny having signed the message.

This technology is the backbone of secure software downloads, online banking, and legally-binding digital contracts.

✨ Key Features
🔑 Generate RSA Keys: Instantly create a new 2048-bit RSA public/private key pair.

✍️ Sign Documents: Generate a unique, secure signature for any piece of text using your secret private key.

✅ Verify Signatures: Confirm that a document is authentic and untampered with by using the sender's public key.

⚙️ How It Works Cryptographically
The application follows the standard, secure process for digital signatures:

Hashing: The original message is first run through the SHA-256 algorithm to create a unique, fixed-size fingerprint (a hash).

Signing (Encryption): This hash is then encrypted using the sender's private key. The result is the digital signature.

Verification (Decryption): The recipient uses the sender's public key to decrypt the signature, revealing the original hash. They then independently hash the original message themselves. If the two hashes match, the signature is valid!

🚀 Getting Started
This is a desktop application and must be run on your computer, not in a web browser.

Prerequisites
You must have Python 3 installed on your system.

Installation & Launch
Download the Code:

Click the green <> Code button on this repository's main page.

Select Download ZIP and extract it on your computer.

Alternatively, for Git users: git clone https://github.com/your-username/your-repo-name.git

Navigate to the Directory:

Open your terminal or command prompt and use the cd command to move into the project folder you just downloaded.

Install the Required Library:

Run the following command to install the cryptography package:

pip install cryptography

Run the Application:

Execute the script to launch the GUI:

python digital_signature_app.py

The application window should now be open on your screen!

🛠️ Built With
Python 3

Tkinter - For the graphical user interface (GUI).

Cryptography - A powerful Python library for cryptographic recipes and primitives.
