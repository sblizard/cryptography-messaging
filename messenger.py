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
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


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
        self.RK, self.CKs = self.KDF_RK(dh_out=self.DH_exchange(DHs_sk, DHr_pk))
        self.CKr: bytes = b""
        self.Ns: int = 0
        self.Nr: int = 0
        self.PN: int = 0

    def KDF_RK(self, dh_out: bytes) -> tuple[bytes, bytes]:
        hkdf: HKDF = HKDF(
            SHA256(), length=32, salt=self.RK, info=b"messenger kdf"
        )  # NOTE: what to use for info?
        ck: bytes = hkdf.derive(dh_out)
        rk: bytes = ck
        return ck, rk

    def KDF_CK(self, ck: bytes) -> bytes:
        hkdf: HKDF = HKDF(
            SHA256(), length=32, salt=ck, info=b"messenger kdf"
        )  # NOTE: what to use for info?
        return hkdf.derive(ck)

    def DH_exchange(
        self, DHs_sk: EllipticCurvePrivateKey, DHr_pk: EllipticCurvePublicKey
    ) -> bytes:
        return DHs_sk.exchange(ECDH(), DHr_pk)

    def encryptMessage(self, mk: bytes, plaintext: str, message_counter: int) -> bytes:
        aesgcm: AESGCM = AESGCM(mk)
        return aesgcm.encrypt(
            message_counter.to_bytes(12, "big"), plaintext.encode("utf-8"), None
        )


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
