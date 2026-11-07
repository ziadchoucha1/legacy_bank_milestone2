"""Legacy Bank TCP client: encrypts and sends a test transaction using DES-ECB."""
import socket
import struct
from des_common import encrypt_message

SERVER_HOST = "127.0.0.1"  # Change to the server's IP on another machine.
SERVER_PORT = 5000

TRANSACTION = "TXN=TX1001;FROM=ACC100;TO=ACC200;AMOUNT=250.00;CURRENCY=EGP"


def main() -> None:
    plaintext = TRANSACTION.encode("utf-8")
    ciphertext = encrypt_message(plaintext)

    print(f"[CLIENT] Plaintext transaction: {TRANSACTION}")
    print(f"[CLIENT] Ciphertext (hex): {ciphertext.hex().upper()}")

    with socket.create_connection((SERVER_HOST, SERVER_PORT), timeout=10) as client:
        # Send a 4-byte length prefix followed by the ciphertext bytes.
        client.sendall(struct.pack("!I", len(ciphertext)) + ciphertext)
        response = client.recv(1024)
        print(f"[CLIENT] Server response: {response.decode('utf-8', errors='replace')}")


if __name__ == "__main__":
    main()
