import os, socket, threading, queue, tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime
from user import User
from crypto_utils import (
    rsa_wrap_aes_key, rsa_unwrap_aes_key,
    sign_message, verify_signature,
    aes_encrypt_gcm, aes_decrypt_gcm, b64e,
)

class ConnectionWindow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Secure Messenger - Connect")
        self.geometry("360x240")
        self.resizable(True, True)

        ttk.Label(self, text="Nickname").pack(pady=(10, 0))
        self.nick = tk.StringVar(value="Alice")
        ttk.Entry(self, textvariable=self.nick).pack(fill="x", padx=16)

        ttk.Label(self, text="IP address").pack(pady=(10, 0))
        self.ip = tk.StringVar(value="127.0.0.1")
        ttk.Entry(self, textvariable=self.ip).pack(fill="x", padx=16)

        ttk.Label(self, text="Port").pack(pady=(10, 0))
        self.port = tk.StringVar(value="9999")
        ttk.Entry(self, textvariable=self.port).pack(fill="x", padx=16)

        btns = ttk.Frame(self); btns.pack(pady=12)
        ttk.Button(btns, text="Host", command=self._host).grid(row=0, column=0, padx=8)
        ttk.Button(btns, text="Connect", command=self._connect).grid(row=0, column=1, padx=8)

    def _host(self):
        nick = self.nick.get().strip() or "Host"
        port = int(self.port.get())
        self.destroy()  # close connection window immediately
        ChatWindow(nick, "host", "0.0.0.0", port).mainloop()

    def _connect(self):
        nick = self.nick.get().strip() or "Client"
        ip = self.ip.get().strip()
        port = int(self.port.get())
        self.destroy()  # close connection window immediately
        ChatWindow(nick, "client", ip, port).mainloop()

class ChatWindow(tk.Tk):
    def __init__(self, nickname: str, mode: str, ip: str, port: int):
        super().__init__()
        self.title(f"Secure Messenger - {nickname}")
        self.geometry("520x400")
        self.nickname, self.mode, self.ip, self.port = nickname, mode, ip, port

        self.me = User(nickname, rsa_bits=2048)
        self.peer_pem = None
        self.session_key = None

        self.sock = None
        self.rx_q = queue.Queue()
        self.stop = threading.Event()

        self._build_ui()
        self._start_network()

    def _build_ui(self):
        self.columnconfigure(0, weight=1)
        top = ttk.Frame(self); top.grid(row=0, column=0, sticky="ew")
        self.status = tk.StringVar(value="Disconnected")
        ttk.Label(top, textvariable=self.status).pack(side="left", padx=8, pady=6)

        self.canvas = tk.Canvas(self, bg="#f5f6f7", highlightthickness=0)
        self.canvas.grid(row=1, column=0, sticky="nsew"); self.rowconfigure(1, weight=1)
        self.scroll = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.scroll.grid(row=1, column=1, sticky="ns"); self.canvas.configure(yscrollcommand=self.scroll.set)
        self.msg_frame = ttk.Frame(self.canvas)
        self.canvas.create_window((0, 0), window=self.msg_frame, anchor="nw")
        self.msg_frame.bind("<Configure>", lambda e: self.canvas.configure(scrollregion=self.canvas.bbox("all")))

        bottom = ttk.Frame(self); bottom.grid(row=2, column=0, sticky="ew", padx=6, pady=6)
        self.entry = ttk.Entry(bottom); self.entry.grid(row=0, column=0, sticky="ew"); bottom.columnconfigure(0, weight=1)
        ttk.Button(bottom, text="Send", command=self._on_send).grid(row=0, column=1, padx=6)

    def _start_network(self):
        if self.mode == "host":
            threading.Thread(target=self._host_loop, daemon=True).start()
        else:
            threading.Thread(target=self._client_loop, daemon=True).start()
        self.after(100, self._poll_rx)

    def _host_loop(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            srv.bind((self.ip, self.port)); srv.listen(1)
            self.status.set(f"Hosting on {self.ip}:{self.port} …")
            conn, addr = srv.accept(); self.sock = conn
            self.status.set(f"Connected: {addr[0]}:{addr[1]}")
            self._handshake_host()
            self._recv_loop()
        except Exception as e:
            self.status.set(f"Error: {e}")

    def _client_loop(self):
        try:
            conn = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            conn.connect((self.ip, self.port)); self.sock = conn
            self.status.set(f"Connected to {self.ip}:{self.port}")
            self._handshake_client()
            self._recv_loop()
        except Exception as e:
            self.status.set(f"Error: {e}")

    def _handshake_host(self):
        client_pem = self._recv_bytes()
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        peer_pub = load_pem_public_key(client_pem); self.peer_pem = client_pem
        self._send_bytes(self.me.public_pem())
        session = os.urandom(32)
        wrapped = rsa_wrap_aes_key(session, peer_pub)
        self._send_bytes(wrapped)
        self.session_key = session
        # notify success (UI thread)
        self.after(0, lambda: messagebox.showinfo("Connection", "Secure connection established."))

    def _handshake_client(self):
        self._send_bytes(self.me.public_pem())
        server_pem = self._recv_bytes()
        wrapped = self._recv_bytes()
        session = rsa_unwrap_aes_key(wrapped, self.me.private_key)
        self.session_key = session; self.peer_pem = server_pem
        # notify success (UI thread)
        self.after(0, lambda: messagebox.showinfo("Connection", "Secure connection established."))

    def _on_send(self):
        text = self.entry.get().strip()
        if not text or not self.sock or not self.session_key:
            return
        self.entry.delete(0, tk.END)
        self._add_bubble(self.nickname, text, mine=True, ok=True)

        msg = text.encode("utf-8")
        iv, ct, tag = aes_encrypt_gcm(msg, self.session_key)
        sig = sign_message(msg, self.me.private_key)
        packet = b"|".join([
            b64e(iv).encode(),
            b64e(ct).encode(),
            b64e(tag).encode(),
            b64e(sig).encode(),
            self.nickname.encode()
        ])
        self._send_bytes(packet)

    def _recv_loop(self):
        try:
            while not self.stop.is_set():
                data = self._recv_bytes()
                if not data:
                    break
                self.rx_q.put(data)
        finally:
            self.status.set("Disconnected")

    def _poll_rx(self):
        from base64 import b64decode
        while not self.rx_q.empty():
            data = self.rx_q.get()
            try:
                iv_b64, ct_b64, tag_b64, sig_b64, nick = data.split(b"|", 4)
                iv, ct, tag, sig = b64decode(iv_b64), b64decode(ct_b64), b64decode(tag_b64), b64decode(sig_b64)
                plain = aes_decrypt_gcm(iv, ct, tag, self.session_key)
                ok = self._verify_with_peer(plain, sig)
                self._add_bubble(nick.decode(), plain.decode("utf-8"), mine=False, ok=ok)
            except Exception as e:
                self._add_bubble("Peer", f"[Error parsing packet: {e}]", mine=False, ok=False)
        self.after(100, self._poll_rx)

    def _verify_with_peer(self, message_bytes: bytes, signature: bytes) -> bool:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        if not self.peer_pem:
            return False
        peer_pub = load_pem_public_key(self.peer_pem)
        return verify_signature(message_bytes, signature, peer_pub)

    def _send_bytes(self, b: bytes):
        if not self.sock:
            return
        l = len(b).to_bytes(4, "big")
        self.sock.sendall(l + b)

    def _recv_bytes(self) -> bytes:
        if not self.sock:
            return b""
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

    def _add_bubble(self, nick: str, text: str, mine: bool, ok: bool):
        wrap = ttk.Frame(self.msg_frame)
        wrap.pack(fill="x", padx=10, pady=8, anchor="e" if mine else "w")
        head = ttk.Frame(wrap); head.pack(anchor="e" if mine else "w")
        icon = tk.Canvas(head, width=24, height=24, bg="#f5f6f7", highlightthickness=0)
        icon.create_oval(2, 2, 22, 22, fill="#4caf50" if mine else "#607d8b", outline="")
        icon.create_text(12, 12, text=(nick[:1].upper()), fill="white")
        icon.pack(side="right" if mine else "left")
        ttk.Label(head, text=nick, foreground="#333").pack(side="right" if mine else "left", padx=6)

        bg = "#d1f1ff" if mine else "#ffffff"
        status = "✓" if ok else "✗"
        ts = datetime.now().strftime("%H:%M:%S")
        bubble = tk.Label(wrap, text=f"{text}\n{ts} {status}", bg=bg, fg="#111", padx=12, pady=8, justify="left")
        bubble.pack(side="right" if mine else "left")
        self.canvas.yview_moveto(1.0)

def run_gui():
    ConnectionWindow().mainloop()