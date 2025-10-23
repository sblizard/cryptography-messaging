# internal

# external
import hashlib
import hmac
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

# built-in
import os
import pickle


class Report:
    def __init__(self, user: str, content: str):
        self.user = user
        self.content = content

    def __str__(self):
        return f"Report(user={self.user}, content={self.content})"

    @staticmethod
    def serialize(report: "Report") -> bytes:
        return pickle.dumps(report)

    @staticmethod
    def deserialize(data: bytes) -> "Report":
        return pickle.loads(data)


class MessageHeader:
    def __init__(
        self,
        dh_public_key: EllipticCurvePublicKey,
        pn: int,
        n: int,
        encrypted_sk: bytes | None = None,
    ):
        self.dh: EllipticCurvePublicKey = dh_public_key
        self.pn: int = pn
        self.n: int = n
        self.encrypted_sk: bytes | None = encrypted_sk

    def __str__(self):
        return f"MessageHeader(dh={self.dh}, pn={self.pn}, n={self.n}, encrypted_sk={self.encrypted_sk})"

    @staticmethod
    def serialize(header: "MessageHeader") -> bytes:
        dh_bytes = header.dh.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        pn_bytes = header.pn.to_bytes(4, "big")
        n_bytes = header.n.to_bytes(4, "big")

        if header.encrypted_sk is not None:
            encrypted_sk_len = len(header.encrypted_sk).to_bytes(4, "big")
            return (
                dh_bytes + pn_bytes + n_bytes + encrypted_sk_len + header.encrypted_sk
            )
        else:
            encrypted_sk_len = (0).to_bytes(4, "big")
            return dh_bytes + pn_bytes + n_bytes + encrypted_sk_len

    @staticmethod
    def deserialize(data: bytes) -> "MessageHeader":
        dh_pk = EllipticCurvePublicKey.from_encoded_point(SECP256R1(), data[:65])
        pn = int.from_bytes(data[65:69], "big")
        n = int.from_bytes(data[69:73], "big")
        encrypted_sk_len = int.from_bytes(data[73:77], "big")

        if encrypted_sk_len > 0:
            encrypted_sk = data[77 : 77 + encrypted_sk_len]
            return MessageHeader(dh_pk, pn, n, encrypted_sk)
        else:
            return MessageHeader(dh_pk, pn, n)


class Certificate:
    def __init__(self, name: str, pk: EllipticCurvePublicKey):
        self.__name = name
        self.__pk = pk

    def __str__(self):
        return f"Certificate({self.__name}, {self.__pk})"

    def getUserName(self):
        return self.__name

    def getPublicKey(self):
        return self.__pk


class Connection:
    def __init__(self):
        """Initialize an empty connection."""
        self.DHs_sk: EllipticCurvePrivateKey | None = None
        self.DHr_pk: EllipticCurvePublicKey | None = None
        self.RK: bytes | None = None
        self.CKs: bytes | None = None
        self.CKr: bytes | None = None
        self.Ns: int = 0
        self.Nr: int = 0
        self.PN: int = 0
        self.mk: bytes | None = None
        self.sk_encrypted: bytes | None = None

    @classmethod
    def RatchetInitAliceFromScratch(cls, bob_dh_public_key: EllipticCurvePublicKey):
        conn = cls()
        conn.DHs_sk = GENERATE_DH()
        conn.DHr_pk = bob_dh_public_key
        SK = DH(conn.DHs_sk, conn.DHr_pk)
        conn.RK, conn.CKs = KDF_RK(rk=SK, dh_out=SK)
        conn.CKr = None
        conn.Ns = 0
        conn.Nr = 0
        conn.PN = 0
        return conn

    @classmethod
    def RatchetInitBob(cls, SK: bytes, bob_dh_key_pair: EllipticCurvePrivateKey):
        """Initialize a connection for Bob."""
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
        Ns, mk = self.RatchetSendKey()
        header: MessageHeader = HEADER(self.DHs_sk, self.PN, Ns, None)
        ct = ENCRYPT(mk, plaintext, CONCAT(associated_data, header))
        self.mk = None
        return header, ct

    def RatchetReceiveKey(self, header: MessageHeader) -> bytes:
        if not _same_pub(header.dh, self.DHr_pk):
            self.DHRatchet(header)
        if self.CKr is None:
            raise Exception("CKr is None")
        self.CKr, self.mk = KDF_CK(self.CKr)
        self.Nr += 1
        return self.mk

    def RatchetDecrypt(
        self, header: MessageHeader, ciphertext: bytes, associated_data: bytes
    ) -> str:
        mk: bytes = self.RatchetReceiveKey(header)
        return DECRYPT(mk, ciphertext, CONCAT(associated_data, header))

    def DHRatchet(self, header: MessageHeader):
        if self.DHs_sk is None or self.RK is None:
            raise Exception("DHRatchet precondition failed")
        self.PN = self.Ns
        self.Ns = 0
        self.Nr = 0
        self.DHr_pk = header.dh
        self.RK, self.CKr = KDF_RK(self.RK, DH(self.DHs_sk, self.DHr_pk))
        self.DHs_sk = GENERATE_DH()
        self.RK, self.CKs = KDF_RK(self.RK, DH(self.DHs_sk, self.DHr_pk))


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
        eph_pk: EllipticCurvePublicKey = EllipticCurvePublicKey.from_encoded_point(
            SECP256R1(), ct[:65]
        )
        iv: bytes = ct[65:77]
        encrypted: bytes = ct[77:]

        shared: bytes = self.server_decryption_key.exchange(ECDH(), eph_pk)

        hkdf_key: bytes = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"COMP537-Report-Enc-v1",
        ).derive(shared)

        aesgcm: AESGCM = AESGCM(hkdf_key)
        report_bytes = aesgcm.decrypt(
            iv,
            encrypted,
            eph_pk.public_bytes(
                serialization.Encoding.X962,
                serialization.PublicFormat.UncompressedPoint,
            ),
        )

        report: Report = Report.deserialize(report_bytes)
        return str(report)

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
            self.certs[certificate.getUserName()] = certificate
        except Exception as e:
            raise Exception(f"certificate verification failed error: {e}")

    def sendMessage(self, name: str, message: str) -> tuple[bytes, bytes]:
        if name not in self.certs:
            raise Exception(
                f"No certificate found for user '{name}'. Did you call receiveCertificate()?"
            )

        if name not in self.conns:
            bob_public_key: EllipticCurvePublicKey = self.certs[name].getPublicKey()
            conn: Connection = Connection.RatchetInitAliceFromScratch(bob_public_key)
            self.conns[name] = conn
        else:
            conn = self.conns[name]

        header, ciphertext = conn.RatchetEncrypt(plaintext=message, associated_data=b"")
        return MessageHeader.serialize(header), ciphertext

    def receiveMessage(self, name: str, header: bytes, ciphertext: bytes) -> str | None:
        try:
            messageHeader: MessageHeader = MessageHeader.deserialize(header)
            if name not in self.certs:
                raise Exception("no certificate for user")

            if name not in self.conns:
                sk: bytes = self.DHs.exchange(ECDH(), messageHeader.dh)
                conn: Connection = Connection.RatchetInitBob(
                    SK=sk, bob_dh_key_pair=self.DHs
                )
                self.conns[name] = conn
            else:
                conn = self.conns[name]

            if not _same_pub(messageHeader.dh, conn.DHr_pk):
                if messageHeader.n != 0:
                    return None
            else:
                if messageHeader.n != conn.Nr:
                    return None

            msg = conn.RatchetDecrypt(messageHeader, ciphertext, b"")
            return msg

        except Exception:
            return None

    def report(self, name: str, message: str) -> tuple[str, bytes]:
        report: Report = Report(name, message)
        report_bytes: bytes = Report.serialize(report)

        eph_sk: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
        eph_pk_bytes: bytes = eph_sk.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )

        shared: bytes = eph_sk.exchange(ECDH(), self.server_encryption_pk)

        hkdf_key: bytes = HKDF(
            algorithm=SHA256(),
            length=32,
            salt=None,
            info=b"COMP537-Report-Enc-v1",
        ).derive(shared)

        iv: bytes = os.urandom(12)
        aesgcm: AESGCM = AESGCM(hkdf_key)
        ciphertext: bytes = aesgcm.encrypt(iv, report_bytes, eph_pk_bytes)

        full_ct: bytes = eph_pk_bytes + iv + ciphertext
        return str(report), full_ct


def GENERATE_DH() -> EllipticCurvePrivateKey:
    return generate_private_key(SECP256R1())


def KDF_RK(rk: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    hkdf: HKDF = HKDF(
        algorithm=SHA256(),
        length=64,
        salt=rk,
        info="messenger ratchet".encode("utf-8"),
    )
    out: bytes = hkdf.derive(dh_out)
    return out[:32], out[32:]


def KDF_CK(ck: bytes) -> tuple[bytes, bytes]:
    new_ck: bytes = hmac.new(ck, b"\x00", hashlib.sha256).digest()
    mk: bytes = hmac.new(ck, b"\x01", hashlib.sha256).digest()
    return new_ck, mk


def DH(DHs_sk: EllipticCurvePrivateKey, DHr_pk: EllipticCurvePublicKey) -> bytes:
    return DHs_sk.exchange(ECDH(), DHr_pk)


def HEADER(
    dh_pair: EllipticCurvePrivateKey,
    pn: int,
    ns: int,
    encrypted_sk: bytes | None = None,
) -> MessageHeader:
    return MessageHeader(dh_pair.public_key(), pn, ns, encrypted_sk)


def CONCAT(associated_data: bytes, header: MessageHeader) -> bytes:
    header_bytes = MessageHeader.serialize(header)
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


def encrypt_with_public_key(data: bytes, public_key: EllipticCurvePublicKey) -> bytes:
    epheral_private_key: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
    epheral_public_key: EllipticCurvePublicKey = epheral_private_key.public_key()

    shared_key = epheral_private_key.exchange(ECDH(), public_key)

    hkdf: HKDF = HKDF(
        SHA256(),
        length=32,
        salt=None,
        info="messenger encryption".encode("utf-8"),
    )
    aes_key: bytes = hkdf.derive(shared_key)

    aesgcm: AESGCM = AESGCM(aes_key)
    nonce: bytes = os.urandom(12)
    ct: bytes = aesgcm.encrypt(nonce, data, None)

    return (
        epheral_public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint,
        )
        + nonce
        + ct
    )


def decrypt_with_private_key(
    encrypted_data: bytes, private_key: EllipticCurvePrivateKey
) -> bytes:
    epheral_public_key = EllipticCurvePublicKey.from_encoded_point(
        SECP256R1(), encrypted_data[:65]
    )
    nonce = encrypted_data[65:77]
    ct = encrypted_data[77:]

    shared_key = private_key.exchange(ECDH(), epheral_public_key)

    hkdf: HKDF = HKDF(
        SHA256(),
        length=32,
        salt=None,
        info="messenger encryption".encode("utf-8"),
    )
    aes_key: bytes = hkdf.derive(shared_key)

    aesgcm: AESGCM = AESGCM(aes_key)
    pt: bytes = aesgcm.decrypt(nonce, ct, None)

    return pt


def _pk_bytes(pk: EllipticCurvePublicKey) -> bytes:
    return pk.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint,
    )


def _same_pub(
    a: EllipticCurvePublicKey | None, b: EllipticCurvePublicKey | None
) -> bool:
    if a is None or b is None:
        return False
    return _pk_bytes(a) == _pk_bytes(b)
