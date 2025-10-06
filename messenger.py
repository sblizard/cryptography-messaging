import os
import pickle
import string

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDSA,
    SECP256R1,
    generate_private_key,
)
from cryptography.hazmat.primitives.hashes import SHA256


class Certificate:
    def __init__(self, name, pk):
        self.__name = name
        self.__pk = pk

    def __toString__(self):
        return f"Certificate({self.__name}, {self.__pk})"

    def getUserName(self):
        return self.__name

    def getPublicKey(self):
        return self.__pk


class MessengerServer:
    def __init__(
        self,
        server_signing_key: EllipticCurvePrivateKey,
        server_decryption_key: EllipticCurvePrivateKey,
    ):
        self.server_signing_key: EllipticCurvePrivateKey = server_signing_key
        self.server_decryption_key: EllipticCurvePrivateKey = server_decryption_key

    def decryptReport(self, ct: bytes) -> str:
        raise Exception("not implemented!")
        return

    def signCert(self, cert: Certificate) -> bytes:
        return self.server_signing_key.sign(
            data=pickle.dumps(cert), signature_algorithm=ECDSA(SHA256())
        )


class MessengerClient:

    def __init__(
        self,
        name,
        server_signing_pk: EllipticCurvePublicKey,
        server_encryption_pk: EllipticCurvePublicKey,
    ):
        self.name: str = name
        self.server_signing_pk: EllipticCurvePublicKey = server_signing_pk
        self.server_encryption_pk: EllipticCurvePublicKey = server_encryption_pk
        self.conns: dict[str, EllipticCurvePublicKey] = {}  # TYPES ARE WIP
        self.certs: dict[str, Certificate] = {}  # TYPES ARE WIP

        self.DHs: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
        self.DHr: dict[str, EllipticCurvePublicKey] = {}  # TYPES ARE WIP

    def generateCertificate(self) -> Certificate:
        return Certificate(self.name, self.DHs.public_key())

    def receiveCertificate(self, certificate: Certificate, signature: bytes) -> None:
        raise Exception("not implemented!")
        return

    def sendMessage(self, name: str, message: str) -> tuple[bytes, bytes]:
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name: str, header: bytes, ciphertext: bytes) -> str | None:
        raise Exception("not implemented!")
        return

    def report(self, name: str, message: str) -> tuple[str, bytes]:
        raise Exception("not implemented!")
        return
