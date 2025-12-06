from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

class User:
    def __init__(self, name: str, rsa_bits: int = 2048):
        self.name = name
        self._private_key = rsa.generate_private_key(public_exponent=65537, key_size=rsa_bits)
        self._public_key = self._private_key.public_key()
        self.peer_public_key = None
        self.session_key = None  

    def public_pem(self) -> bytes:
        return self._public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def load_peer_public_pem(self, pem: bytes):
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        self.peer_public_key = load_pem_public_key(pem)

    @property
    def private_key(self):
        return self._private_key

    @property
    def public_key(self):
        return self._public_key