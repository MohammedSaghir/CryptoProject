import os, socket, threading, queue, tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import base64

def b64e(b):
    return base64.b64encode(b).decode("ascii")

class IntruderWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MITM Intruder - Fake Client")
        self.geometry("400x300")
        self.resizable(True, True)

        ttk.Label(self, text="Target IP address").pack(pady=(10, 0))
        self.ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(self, textvariable=self.ip).pack(fill="x", padx=16)

        ttk.Label(self, text="Target Port").pack(pady=(10, 0))
        self.port = tk.StringVar(value="9999")
        ttk.Entry(self, textvariable=self.port).pack(fill="x", padx=16)

        ttk.Label(self, text="Fake Nickname").pack(pady=(10, 0))
        self.nickname = tk.StringVar(value="Intruder")
        ttk.Entry(self, textvariable=self.nickname).pack(fill="x", padx=16)

        self.status = tk.StringVar(value="Disconnected")
        ttk.Label(self, textvariable=self.status).pack(pady=8)

        self.entry = ttk.Entry(self)
        self.entry.pack(fill="x", padx=16, pady=(8, 0))
        ttk.Button(self, text="Send Forged Message", command=self._on_send).pack(pady=8)

        self.sock = None
        self.session_key = None
        self.connected = False
        self._generate_fake_key()
        threading.Thread(target=self._connect_and_handshake, daemon=True).start()

    def _generate_fake_key(self):
        # Generate a fake RSA key pair for handshake
        self.fake_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.fake_public_key = self.fake_private_key.public_key()
        self.fake_public_pem = self.fake_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def _connect_and_handshake(self):
        try:
            ip = self.ip.get().strip()
            port = int(self.port.get())
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            self.sock = s
            self.status.set(f"Connected to {ip}:{port}")
            # Send our fake public key
            self._send_bytes(self.fake_public_pem)
            # Receive server's public key
            server_pem = self._recv_bytes()
            # Receive wrapped session key
            wrapped = self._recv_bytes()
            # We can't unwrap the session key, so just generate a random one (forged messages will fail decryption anyway)
            self.session_key = os.urandom(32)
            self.connected = True
            self.status.set("Handshake complete. Ready to inject.")
        except Exception as e:
            self.status.set(f"Error: {e}")
            self.sock = None

    def _on_send(self):
        if not self.sock or not self.connected:
            messagebox.showerror("Not connected", "Not connected to target.")
            return
        text = self.entry.get().strip()
        if not text:
            return
        # Forge a message: random IV, CT, tag, sig
        iv = os.urandom(12)
        ct = os.urandom(32)
        tag = os.urandom(16)
        sig = os.urandom(256)  # Not a real signature
        nickname = self.nickname.get().strip() or "Intruder"
        packet = b"|".join([
            b64e(iv).encode(),
            b64e(ct).encode(),
            b64e(tag).encode(),
            b64e(sig).encode(),
            nickname.encode()
        ])
        try:
            self._send_bytes(packet)
            self.status.set("Forged message sent!")
        except Exception as e:
            self.status.set(f"Send error: {e}")

    def _send_bytes(self, b: bytes):
        l = len(b).to_bytes(4, "big")
        self.sock.sendall(l + b)

    def _recv_bytes(self) -> bytes:
        hdr = self._recv_exact(4)
        if not hdr:
            return b""
        ln = int.from_bytes(hdr, "big")
        return self._recv_exact(ln)

    def _recv_exact(self, n: int) -> bytes:
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

def run_gui():
    IntruderWindow().mainloop()

if __name__ == "__main__":
    run_gui()
import socket
import base64
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

# Generate a key pair
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

# Export public key in PEM format
public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

# Change these to match your app's host and port
HOST = "127.0.0.1"
PORT = 9999

def b64e(b):
    return base64.b64encode(b).decode("ascii")

def main():
    # Create a fake packet (invalid signature/tag)
    iv = os.urandom(12)
    ct = os.urandom(32)
    tag = os.urandom(16)
    sig = os.urandom(256)  # Not a real signature
    nickname = "Intruder"

    # Build the packet as your app expects (b64, separated by b"|")
    packet = b"|".join([
        b64e(iv).encode(),
        b64e(ct).encode(),
        b64e(tag).encode(),
        b64e(sig).encode(),
        nickname.encode()
    ])

    # Send the packet to the server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        # Send our public key to complete handshake (send random bytes)
        s.sendall(len(b"FAKEKEY").to_bytes(4, "big") + b"FAKEKEY")
        # Receive server's public key
        hdr = s.recv(4)
        ln = int.from_bytes(hdr, "big")
        s.recv(ln)
        # Receive wrapped session key
        hdr = s.recv(4)
        ln = int.from_bytes(hdr, "big")
        s.recv(ln)
        # Now send the forged message
        s.sendall(len(packet).to_bytes(4, "big") + packet)

if __name__ == "__main__":
    main()