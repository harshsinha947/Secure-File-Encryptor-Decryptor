**Project Title:**

Secure File Encryption & Hashing Application (AES-256 & SHA-256)

**Project Description:**

A desktop application built with Python and Tkinter for secure file encryption and decryption, designed to protect sensitive data while maintaining file integrity. This application combines strong AES-256 encryption with SHA-256 hashing to ensure both confidentiality and authenticity of files.

Key features include:

AES-256 Encryption/Decryption: Symmetric key encryption ensures that any file (text, PDF, images, videos, etc.) can be securely encrypted and decrypted using a password.

Original File Restoration: Decrypted files retain their original name, extension, and content, making the decryption process seamless.

SHA-256 Hashing: Generates the cryptographic hash of the original or decrypted file, allowing users to verify the integrity of the file and ensure it hasn’t been tampered with.

User-Friendly GUI: Modern, dark-themed interface with intuitive file selection, password input, and clear display of encryption/decryption results.

Secure Key Derivation: Uses PBKDF2 to derive AES keys from passwords, adding extra protection against brute-force attacks.

Technologies Used:

Python 3

Tkinter for GUI

PyCryptodome for AES encryption and cryptographic functions

hashlib for SHA-256 hashing

Learning Outcomes / Skills Demonstrated:

Implementing strong symmetric encryption and key management.

Working with binary file operations and preserving file metadata.

Integrating cryptographic hashing to verify file integrity.

Building interactive GUI applications in Python.

Enhancing user experience with modern and attractive interface design.

This project is ideal for demonstrating knowledge in cybersecurity, cryptography, and software development, and it can be expanded further to support folder encryption, progress bars for large files, or multi-platform deployment.
