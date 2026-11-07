"""
Shared DES-ECB helpers for the Legacy Bank Milestone 2 demonstration.
Educational use only: DES and ECB are insecure for real financial data.
Install: python -m pip install -r requirements.txt
"""
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad

# Static, hardcoded 64-bit (8-byte) DES key shared by Client and Server.
# DES uses 56 effective key bits; 8 bits are parity bits.
KEY = b"Legacy64"
BLOCK_SIZE = DES.block_size  # 8 bytes


def encrypt_message(plaintext: bytes) -> bytes:
    """PKCS#7-pad then encrypt using DES in ECB mode."""
    cipher = DES.new(KEY, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, BLOCK_SIZE))


def decrypt_message(ciphertext: bytes) -> bytes:
    """Decrypt DES-ECB ciphertext and remove PKCS#7 padding."""
    if not ciphertext or len(ciphertext) % BLOCK_SIZE != 0:
        raise ValueError("Ciphertext length must be a positive multiple of 8 bytes.")
    cipher = DES.new(KEY, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), BLOCK_SIZE)
