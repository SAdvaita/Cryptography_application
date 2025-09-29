Digital Signature Verifier
This is a simple Python desktop application that demonstrates how digital signatures work using RSA cryptography. It allows users to generate key pairs, sign messages with a private key, and verify the signature with a public key.

What it Does
Generate RSA Keys: Create a new 2048-bit RSA public/private key pair.

Sign Documents: Create a unique digital signature for any text message using your private key.

Verify Signatures: Check if a message is authentic and has not been altered by verifying its signature with the sender's public key. This is the core of proving authenticity and integrity.

🚀 How to Run This Project
This is a desktop application and must be run on your computer, not in a web browser.

Prerequisites
You must have Python 3 installed.

Steps
Download the Code:

Click the green <> Code button on this repository's main page.

Select Download ZIP.

Extract the ZIP file on your computer.

Open a Terminal or Command Prompt:

Navigate into the folder you just extracted.

Install the Required Library:

Run the following command in your terminal:

pip install cryptography

Run the Application:

Now, run the main script:

python digital_signature_app.py

The application window should now open on your screen!s
