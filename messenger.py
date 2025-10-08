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


class MessageHeader:
    def __init__(self, dh_public_key: EllipticCurvePublicKey, pn: int, n: int):
        self.dh = dh_public_key
        self.pn = pn
        self.n = n

    def serialize(self) -> bytes:
        return (
            self.dh.public_bytes(
                encoding=serialization.Encoding.X962,
                format=serialization.PublicFormat.UncompressedPoint,
            )
            + self.pn.to_bytes(4, "big")
            + self.n.to_bytes(4, "big")
        )


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
    def __init__(self):
        self.DHs_sk: EllipticCurvePrivateKey | None = None
        self.DHr_pk: EllipticCurvePublicKey | None = None
        self.RK: bytes | None = None
        self.CKs: bytes | None = None
        self.CKr: bytes | None = None
        self.Ns: int = 0
        self.Nr: int = 0
        self.PN: int = 0
        self.mk: bytes | None = None

    @classmethod
    def RatchetInitAlice(cls, SK: bytes, bob_dh_public_key: EllipticCurvePublicKey):
        conn: Connection = cls()
        conn.DHs_sk = GENERATE_DH()
        conn.DHr_pk = bob_dh_public_key
        conn.RK, conn.CKs = KDF_RK(rk=SK, dh_out=DH(conn.DHs_sk, conn.DHr_pk))
        conn.CKr = None
        conn.Ns = 0
        conn.Nr = 0
        conn.PN = 0
        return conn

    @classmethod
    def RatchetInitBob(cls, SK: bytes, bob_dh_key_pair: EllipticCurvePrivateKey):
        conn: Connection = cls()
        conn.DHs_sk = bob_dh_key_pair
        conn.DHr_pk = None
        conn.RK = SK
        conn.CKs = None
        conn.CKr = None
        conn.Ns = 0
        conn.Nr = 0
        conn.PN = 0
        return conn

    def __str__(self):
        return f"Connection(DHs_sk={self.DHs_sk}, DHr_pk={self.DHr_pk}, RK={self.RK}, CKs={self.CKs}, CKr={self.CKr}, Ns={self.Ns}, Nr={self.Nr}, PN={self.PN}, mk={self.mk})"

    def RatchetSendKey(self) -> tuple[int, bytes]:
        if self.CKs is None:
            raise Exception("CKs is None")
        self.CKs, self.mk = KDF_CK(ck=self.CKs)
        Ns = self.Ns
        self.Ns += 1
        return Ns, self.mk

    def RatchetEncrypt(
        self, plaintext: str, associated_data: bytes
    ) -> tuple[MessageHeader, bytes]:
        if self.DHs_sk is None:
            raise Exception("DHs_sk is None")
        self.Ns, self.mk = self.RatchetSendKey()
        header: MessageHeader = HEADER(self.DHs_sk, self.PN, self.Ns)
        return header, ENCRYPT(self.mk, plaintext, CONCAT(associated_data, header))


class MessengerServer:
    def __init__(
        self,
        server_signing_key: EllipticCurvePrivateKey,
        server_decryption_key: EllipticCurvePrivateKey,
    ):
        self.server_signing_key: EllipticCurvePrivateKey = server_signing_key
        self.server_decryption_key: EllipticCurvePrivateKey = server_decryption_key

    def __str__(self):
        return f"MessengerServer(server_signing_key={self.server_signing_key}, server_decryption_key={self.server_decryption_key})"

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
        self.conns: dict[str, Connection] = {}
        self.certs: dict[str, Certificate] = {}

        self.DHs: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
        self.DHr: dict[str, EllipticCurvePublicKey] = {}

    def __str__(self) -> str:
        return f"MessengerClient(name={self.name}, server_signing_pk={self.server_signing_pk}, server_encryption_pk={self.server_encryption_pk}, conns={self.conns}, certs={self.certs}, DHs={self.DHs}, DHr={self.DHr})"

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
        if name not in self.certs:
            raise Exception("no certificate for user")
        if name not in self.conns:
            sk: bytes = b""  # NOTE: how to determine shared SK?
            conn: Connection = Connection.RatchetInitAlice(
                SK=sk,
                bob_dh_public_key=self.certs[name].getPublicKey(),
            )
            self.conns[name] = conn
        else:
            conn = self.conns[name]

        header, ciphertext = conn.RatchetEncrypt(
            plaintext=message,
            associated_data=self.name.encode("utf-8") + name.encode("utf-8"),
        )

        return header.serialize(), ciphertext

    def receiveMessage(self, name: str, header: bytes, ciphertext: bytes) -> str | None:
        raise Exception("not implemented!")
        return

    def report(self, name: str, message: str) -> tuple[str, bytes]:
        raise Exception("not implemented!")
        return


def GENERATE_DH() -> EllipticCurvePrivateKey:
    return generate_private_key(SECP256R1())


def KDF_RK(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    hkdf: HKDF = HKDF(
        SHA256(), length=32, salt=rk, info=b"messenger kdf"
    )  # NOTE: what to use for info?
    ck: bytes = hkdf.derive(dh_out)
    rk = ck
    return ck, rk


def KDF_CK(ck: bytes) -> tuple[bytes, bytes]:
    hkdf: HKDF = HKDF(
        SHA256(), length=64, salt=ck, info=b"messenger kdf"
    )  # NOTE: what to use for info?
    return hkdf.derive(ck)[:32], hkdf.derive(ck)[32:]


def DH(DHs_sk: EllipticCurvePrivateKey, DHr_pk: EllipticCurvePublicKey) -> bytes:
    return DHs_sk.exchange(ECDH(), DHr_pk)


def HEADER(dh_pair: EllipticCurvePrivateKey, pn: int, ns: int) -> MessageHeader:
    return MessageHeader(dh_pair.public_key(), pn, ns)


def CONCAT(associated_data: bytes, header: MessageHeader) -> bytes:
    header_bytes: bytes = (
        header.dh.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        + header.pn.to_bytes(4, "big")
        + header.n.to_bytes(4, "big")
    )
    ad_length = len(associated_data).to_bytes(4, "big")

    return ad_length + associated_data + header_bytes


def ENCRYPT(mk: bytes, plaintext: str, associated_data: bytes) -> bytes:
    aesgcm: AESGCM = AESGCM(mk)
    nonce: bytes = os.urandom(12)
    ct: bytes = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), associated_data)
    return nonce + ct


def DECRYPT(mk: bytes, ciphertext: bytes, associated_data: bytes) -> str:
    aesgcm: AESGCM = AESGCM(mk)
    nonce: bytes = ciphertext[:12]
    ct: bytes = ciphertext[12:]
    pt: bytes = aesgcm.decrypt(nonce, ct, associated_data)
    return pt.decode("utf-8")
