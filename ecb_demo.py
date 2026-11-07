"""Appendix B: demonstrate that identical ECB plaintext blocks encrypt identically."""
from Crypto.Cipher import DES
from des_common import KEY

BLOCK = b"PAYMENT!"  # Exactly 8 bytes, one DES block.
cipher = DES.new(KEY, DES.MODE_ECB)
ciphertext = cipher.encrypt(BLOCK + BLOCK)

c1 = ciphertext[:8]
c2 = ciphertext[8:]

print("DES-ECB identical-block demonstration")
print(f"Key (hex):                 {KEY.hex().upper()}")
print(f"Plaintext block 1 (ASCII): {BLOCK.decode('ascii')}")
print(f"Plaintext block 2 (ASCII): {BLOCK.decode('ascii')}")
print(f"Plaintext block 1 (hex):   {BLOCK.hex().upper()}")
print(f"Plaintext block 2 (hex):   {BLOCK.hex().upper()}")
print(f"Ciphertext block 1:        {c1.hex().upper()}")
print(f"Ciphertext block 2:        {c2.hex().upper()}")
print(f"Blocks identical?          {c1 == c2}")
