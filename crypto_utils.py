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

def aes_encrypt_cbc(plaintext: bytes, key: bytes) -> Tuple[bytes, bytes]:
    iv = os.urandom(16)
    padder = padding.PKCS7(128).padder()
    padded = padder.update(plaintext) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    enc = cipher.encryptor()
    ct = enc.update(padded) + enc.finalize()
    return iv, ct

def aes_decrypt_cbc(iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    dec = cipher.decryptor()
    padded = dec.update(ciphertext) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded) + unpadder.finalize()

def make_packet(iv: bytes, ct: bytes, sig: bytes) -> Dict[str, str]:
    return {"iv": b64e(iv), "ct": b64e(ct), "sig": b64e(sig)}

def parse_packet(pkg: Dict[str, str]):
    return b64d(pkg["iv"]), b64d(pkg["ct"]), b64d(pkg["sig"])