import os
import pickle
import string

from cryptography.hazmat.primitives.asymmetric.ec import (
    EllipticCurvePrivateKey,
    EllipticCurvePublicKey,
    ECDSA,
    SECP256R1,
    generate_private_key,
    ECDH,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization


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


class Connection:
    def __init__(
        self,
        DHs_sk: EllipticCurvePrivateKey,
        DHr_pk: EllipticCurvePublicKey,
    ):
        self.DHs_sk: EllipticCurvePrivateKey = DHs_sk
        self.DHr_pk: EllipticCurvePublicKey = DHr_pk
        self.chain_key: bytes = b""
        self.chain_counter: int = 0

    def updateChainKey(self, diffie_hellman_output: bytes) -> bytes:
        hkdf: HKDF = HKDF(
            SHA256(), length=32, salt=self.chain_key, info=b"handshake data"
        )
        self.chain_key = hkdf.derive(diffie_hellman_output)
        self.chain_counter += 1
        return self.chain_key


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
        public_key_bytes: bytes = cert.getPublicKey().public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        cert_data: bytes = cert.getUserName().encode("utf-8") + public_key_bytes

        return self.server_signing_key.sign(
            data=cert_data, signature_algorithm=ECDSA(SHA256())
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
        self.conns: dict[str, EllipticCurvePublicKey] = {}
        self.certs: dict[str, Certificate] = {}

        self.DHs: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
        self.DHr: dict[str, EllipticCurvePublicKey] = {}

    def generateCertificate(self) -> Certificate:
        return Certificate(self.name, self.DHs.public_key())

    def receiveCertificate(self, certificate: Certificate, signature: bytes) -> None:
        try:
            self.server_signing_pk.verify(
                signature=signature,
                data=certificate.getUserName().encode("utf-8")
                + certificate.getPublicKey().public_bytes(
                    encoding=serialization.Encoding.X962,
                    format=serialization.PublicFormat.UncompressedPoint,
                ),
                signature_algorithm=ECDSA(SHA256()),
            )
            # NOTE: Is it okay to store a certiifcate under user name? ie can we assume unique user names?
            self.certs[certificate.getUserName()] = certificate
        except:
            raise Exception("certificate verification failed")

    def sendMessage(self, name: str, message: str) -> tuple[bytes, bytes]:

        return b"", b""

    def receiveMessage(self, name: str, header: bytes, ciphertext: bytes) -> str | None:
        raise Exception("not implemented!")
        return

    def report(self, name: str, message: str) -> tuple[str, bytes]:
        raise Exception("not implemented!")
        return
