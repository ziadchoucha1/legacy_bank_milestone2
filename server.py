"""Legacy Bank TCP server: receives and decrypts one DES-ECB transaction."""
import socket
import struct
from des_common import decrypt_message

HOST = "0.0.0.0"
PORT = 5000
MAX_CIPHERTEXT = 1_000_000


def recv_exact(conn: socket.socket, length: int) -> bytes:
    """TCP is a byte stream, so keep reading until the requested bytes arrive."""
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise ConnectionError("Client disconnected before the message was complete.")
        data.extend(chunk)
    return bytes(data)


def main() -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((HOST, PORT))
        server.listen(5)
        print(f"[SERVER] Listening on {HOST}:{PORT}")
        while True:
            conn, address = server.accept()
            with conn:
                print(f"[SERVER] Connected by {address}")
                try:
                    # Four-byte network-order length prefix frames the ciphertext.
                    ciphertext_length = struct.unpack("!I", recv_exact(conn, 4))[0]
                    if ciphertext_length == 0 or ciphertext_length > MAX_CIPHERTEXT:
                        raise ValueError("Invalid ciphertext length.")
                    ciphertext = recv_exact(conn, ciphertext_length)
                    print(f"[SERVER] Ciphertext (hex): {ciphertext.hex().upper()}")
                    plaintext = decrypt_message(ciphertext)
                    print(f"[SERVER] Decrypted transaction: {plaintext.decode('utf-8')}")
                    conn.sendall(b"ACK: transaction received and decrypted")
                except Exception as exc:
                    print(f"[SERVER] Error: {exc}")
                    conn.sendall(b"ERROR")
                print("[SERVER] Connection closed")


if __name__ == "__main__":
    main()
