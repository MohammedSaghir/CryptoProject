import os, base64
from typing import Tuple, Dict
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as apadding
from cryptography.exceptions import InvalidSignature

def b64e(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def rsa_wrap_aes_key(aes_key: bytes, peer_public_key) -> bytes:
    return peer_public_key.encrypt(
        aes_key,
        apadding.OAEP(
            mgf=apadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def rsa_unwrap_aes_key(wrapped: bytes, private_key) -> bytes:
    return private_key.decrypt(
        wrapped,
        apadding.OAEP(
            mgf=apadding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

def sign_message(message: bytes, private_key) -> bytes:
    return private_key.sign(
        message,
        apadding.PSS(
            mgf=apadding.MGF1(hashes.SHA256()),
            salt_length=apadding.PSS.MAX_LENGTH,
        ),
        hashes.SHA256(),
    )

def verify_signature(message: bytes, signature: bytes, public_key) -> bool:
    try:
        public_key.verify(
            signature,
            message,
            apadding.PSS(
                mgf=apadding.MGF1(hashes.SHA256()),
                salt_length=apadding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        return True
    except InvalidSignature:
        return False

def aes_encrypt_gcm(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv))
    enc = cipher.encryptor()
    ct = enc.update(plaintext) + enc.finalize()
    tag = enc.tag
    return iv, ct, tag

def aes_decrypt_gcm(iv: bytes, ciphertext: bytes, tag: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag))
    dec = cipher.decryptor()
    return dec.update(ciphertext) + dec.finalize()

def make_packet(iv: bytes, ct: bytes, tag: bytes, sig: bytes) -> Dict[str, str]:
    return {"iv": b64e(iv), "ct": b64e(ct), "tag": b64e(tag), "sig": b64e(sig)}

def parse_packet(pkg: Dict[str, str]):
    return b64d(pkg["iv"]), b64d(pkg["ct"]), b64d(pkg["tag"]), b64d(pkg["sig"])