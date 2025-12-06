import os
from user import User
from crypto_utils import (
    rsa_wrap_aes_key, rsa_unwrap_aes_key,
    sign_message, verify_signature,
    aes_encrypt_cbc, aes_decrypt_cbc,
    make_packet, parse_packet, b64e
)

def handshake(alice: User, bob: User):
    # Exchange public keys (PEM)
    bob.load_peer_public_pem(alice.public_pem())
    alice.load_peer_public_pem(bob.public_pem())

    # Alice creates AES-256 session key
    session_key = os.urandom(32)
    # Encrypt with Bob's public key (stored in alice.peer_public_key)
    wrapped = rsa_wrap_aes_key(session_key, alice.peer_public_key)
    # Bob unwraps with his private key
    bob.session_key = rsa_unwrap_aes_key(wrapped, bob.private_key)
    # Alice stores her own session key
    alice.session_key = session_key

def send_secure(sender: User, receiver: User, text: str):
    msg = text.encode("utf-8")
    iv, ct = aes_encrypt_cbc(msg, sender.session_key)
    sig = sign_message(msg, sender.private_key)
    pkg = make_packet(iv, ct, sig)
    print(f"\n[{sender.name} → {receiver.name}] packet (b64): {pkg}")
    # Receiver side
    riv, rct, rsig = parse_packet(pkg)
    plain = aes_decrypt_cbc(riv, rct, receiver.session_key)
    ok = verify_signature(plain, rsig, sender.public_key)
    print(f"[{receiver.name}] decrypted: {plain.decode('utf-8')}")
    print(f"[{receiver.name}] signature valid: {ok}")

def demo_chat():
    alice = User("Alice", rsa_bits=2048)
    bob = User("Bob", rsa_bits=2048)
    handshake(alice, bob)
    send_secure(alice, bob, "Hello Bob, this is Alice.")
    send_secure(bob, alice, "Hi Alice, Bob here. AES+RSA FTW!")