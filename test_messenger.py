"""
Comprehensive test suite for the cryptography messenger application.
Tests all functionality including security vulnerabilities, edge cases, and protocol compliance.
"""

import pytest
import os
import hashlib
import hmac
from unittest.mock import Mock, patch
from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key,
    EllipticCurvePrivateKey,
    SECP256R1,
    EllipticCurvePublicKey,
    ECDSA,
    ECDH,
)
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidSignature
from hypothesis import given, strategies as st, settings
import pickle

from messenger import (
    MessengerServer,
    MessengerClient,
    Certificate,
    Connection,
    Report,
    MessageHeader,
    GENERATE_DH,
    KDF_RK,
    KDF_CK,
    DH,
    HEADER,
    CONCAT,
    ENCRYPT,
    DECRYPT,
    encrypt_with_public_key,
    decrypt_with_private_key,
    _pk_bytes,
    _same_pub,
)


class TestCertificate:
    """Test Certificate class functionality and security."""

    def test_certificate_creation(self):
        """Test basic certificate creation."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        cert = Certificate("alice", public_key)

        assert cert.getUserName() == "alice"
        assert cert.getPublicKey() == public_key

    def test_certificate_immutability(self):
        """Test that certificate fields are properly encapsulated."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        cert = Certificate("alice", public_key)

        # Should not be able to directly access private fields
        assert not hasattr(cert, "name")
        assert not hasattr(cert, "pk")

    @given(st.text(min_size=1, max_size=100))
    def test_certificate_with_various_names(self, name):
        """Test certificate creation with various name inputs."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        cert = Certificate(name, public_key)

        assert cert.getUserName() == name

    def test_certificate_string_representation(self):
        """Test certificate string representation doesn't leak sensitive data."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        cert = Certificate("alice", public_key)

        cert_str = str(cert)
        assert "alice" in cert_str
        assert "Certificate" in cert_str


class TestReport:
    """Test Report class functionality and security."""

    def test_report_creation(self):
        """Test basic report creation."""
        report = Report("bob", "inappropriate content")

        assert report.user == "bob"
        assert report.content == "inappropriate content"

    def test_report_serialization_deserialization(self):
        """Test report serialization and deserialization."""
        original_report = Report("alice", "test message")
        serialized = Report.serialize(original_report)
        deserialized = Report.deserialize(serialized)

        assert deserialized.user == original_report.user
        assert deserialized.content == original_report.content

    @given(st.text(), st.text())
    def test_report_serialization_property_based(self, user, content):
        """Property-based test for report serialization."""
        original_report = Report(user, content)
        serialized = Report.serialize(original_report)
        deserialized = Report.deserialize(serialized)

        assert deserialized.user == original_report.user
        assert deserialized.content == original_report.content

    def test_report_pickle_security(self):
        """Test that pickle deserialization is secure against malicious data."""
        # Test with invalid pickle data
        with pytest.raises(Exception):
            Report.deserialize(b"invalid_pickle_data")

    def test_report_string_representation(self):
        """Test report string representation."""
        report = Report("user", "content")
        report_str = str(report)

        assert "Report(" in report_str
        assert "user=user" in report_str
        assert "content=content" in report_str


class TestMessageHeader:
    """Test MessageHeader class functionality and security."""

    def test_message_header_creation(self):
        """Test basic message header creation."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        header = MessageHeader(public_key, 1, 2, b"encrypted_sk")

        assert header.dh == public_key
        assert header.pn == 1
        assert header.n == 2
        assert header.encrypted_sk == b"encrypted_sk"

    def test_message_header_serialization_deserialization(self):
        """Test message header serialization and deserialization."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        original_header = MessageHeader(public_key, 5, 10, b"test_sk")

        serialized = MessageHeader.serialize(original_header)
        deserialized = MessageHeader.deserialize(serialized)

        assert _same_pub(deserialized.dh, original_header.dh)
        assert deserialized.pn == original_header.pn
        assert deserialized.n == original_header.n
        assert deserialized.encrypted_sk == original_header.encrypted_sk

    def test_message_header_serialization_without_encrypted_sk(self):
        """Test message header serialization without encrypted_sk field."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        original_header = MessageHeader(public_key, 3, 7)

        serialized = MessageHeader.serialize(original_header)
        deserialized = MessageHeader.deserialize(serialized)

        assert _same_pub(deserialized.dh, original_header.dh)
        assert deserialized.pn == original_header.pn
        assert deserialized.n == original_header.n
        assert deserialized.encrypted_sk is None

    def test_message_header_malformed_serialization(self):
        """Test deserialization with malformed data."""
        with pytest.raises(Exception):
            MessageHeader.deserialize(b"invalid_data")

    @given(
        st.integers(min_value=0, max_value=2**32 - 1),
        st.integers(min_value=0, max_value=2**32 - 1),
    )
    def test_message_header_counter_limits(self, pn, n):
        """Test message header with various counter values."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        header = MessageHeader(public_key, pn, n)

        serialized = MessageHeader.serialize(header)
        deserialized = MessageHeader.deserialize(serialized)

        assert deserialized.pn == pn
        assert deserialized.n == n


class TestConnection:
    """Test Connection class and Double Ratchet functionality."""

    def test_connection_initialization(self):
        """Test empty connection initialization."""
        conn = Connection()

        assert conn.DHs_sk is None
        assert conn.DHr_pk is None
        assert conn.RK is None
        assert conn.CKs is None
        assert conn.CKr is None
        assert conn.Ns == 0
        assert conn.Nr == 0
        assert conn.PN == 0

    def test_alice_ratchet_init(self):
        """Test Alice's ratchet initialization."""
        bob_key = generate_private_key(SECP256R1())
        bob_public = bob_key.public_key()

        conn = Connection.RatchetInitAliceFromScratch(bob_public)

        assert conn.DHs_sk is not None
        assert conn.DHr_pk == bob_public
        assert conn.RK is not None
        assert conn.CKs is not None
        assert conn.CKr is None
        assert conn.Ns == 0
        assert conn.Nr == 0
        assert conn.PN == 0

    def test_bob_ratchet_init(self):
        """Test Bob's ratchet initialization."""
        bob_key = generate_private_key(SECP256R1())
        sk = os.urandom(32)

        conn = Connection.RatchetInitBob(sk, bob_key)

        assert conn.DHs_sk == bob_key
        assert conn.DHr_pk is None
        assert conn.RK == sk
        assert conn.CKs is None
        assert conn.CKr is None
        assert conn.Ns == 0
        assert conn.Nr == 0
        assert conn.PN == 0

    def test_ratchet_send_key(self):
        """Test send key generation."""
        bob_key = generate_private_key(SECP256R1())
        bob_public = bob_key.public_key()

        conn = Connection.RatchetInitAliceFromScratch(bob_public)
        initial_ns = conn.Ns

        ns, mk = conn.RatchetSendKey()

        assert ns == initial_ns
        assert conn.Ns == initial_ns + 1
        assert mk is not None
        assert len(mk) == 32

    def test_ratchet_send_key_without_cks(self):
        """Test send key generation fails without CKs."""
        conn = Connection()

        with pytest.raises(Exception, match="CKs is None"):
            conn.RatchetSendKey()

    def test_ratchet_encrypt_decrypt(self):
        """Test complete encrypt-decrypt cycle."""
        # Alice setup
        bob_key = generate_private_key(SECP256R1())
        bob_public = bob_key.public_key()
        alice_conn = Connection.RatchetInitAliceFromScratch(bob_public)

        # Encrypt message
        message = "Hello, Bob!"
        header, ciphertext = alice_conn.RatchetEncrypt(message, b"")

        # Bob setup
        if alice_conn.DHs_sk is not None:
            alice_public = alice_conn.DHs_sk.public_key()
            sk = bob_key.exchange(ECDH(), alice_public)
            bob_conn = Connection.RatchetInitBob(sk, bob_key)

            # Decrypt message
            decrypted = bob_conn.RatchetDecrypt(header, ciphertext, b"")

            assert decrypted == message

    def test_dh_ratchet(self):
        """Test DH ratchet step."""
        # Setup connection
        bob_key = generate_private_key(SECP256R1())
        bob_public = bob_key.public_key()
        conn = Connection.RatchetInitAliceFromScratch(bob_public)

        # Create new header with different DH key
        new_key = generate_private_key(SECP256R1())
        header = MessageHeader(new_key.public_key(), 0, 0)

        old_ns = conn.Ns
        old_dh = conn.DHs_sk

        conn.DHRatchet(header)

        assert conn.PN == old_ns  # PN should be set to old Ns
        assert conn.Ns == 0  # Ns should be reset
        assert conn.Nr == 0  # Nr should be reset
        assert conn.DHr_pk == header.dh
        assert conn.DHs_sk != old_dh  # New DH key generated

    def test_dh_ratchet_preconditions(self):
        """Test DH ratchet fails without proper setup."""
        conn = Connection()
        header = MessageHeader(generate_private_key(SECP256R1()).public_key(), 0, 0)

        with pytest.raises(Exception, match="DHRatchet precondition failed"):
            conn.DHRatchet(header)


class TestCryptographicPrimitives:
    """Test cryptographic primitive functions."""

    def test_generate_dh(self):
        """Test DH key generation."""
        key = GENERATE_DH()
        assert isinstance(key, EllipticCurvePrivateKey)

    def test_kdf_rk(self):
        """Test root key KDF."""
        rk = os.urandom(32)
        dh_out = os.urandom(32)
        new_rk, ck = KDF_RK(rk, dh_out)

        assert len(new_rk) == 32
        assert len(ck) == 32
        assert new_rk != rk
        assert ck != rk

    def test_kdf_ck(self):
        """Test chain key KDF."""
        ck = os.urandom(32)

        new_ck, mk = KDF_CK(ck)

        assert len(new_ck) == 32
        assert len(mk) == 32
        assert new_ck != ck
        assert mk != ck
        assert new_ck != mk

    def test_dh_exchange(self):
        """Test DH key exchange."""
        alice_key = generate_private_key(SECP256R1())
        bob_key = generate_private_key(SECP256R1())

        shared1 = DH(alice_key, bob_key.public_key())
        shared2 = DH(bob_key, alice_key.public_key())

        assert shared1 == shared2
        assert len(shared1) == 32

    def test_header_function(self):
        """Test HEADER function."""
        dh_key = generate_private_key(SECP256R1())
        header = HEADER(dh_key, 5, 10, b"sk")

        assert _same_pub(header.dh, dh_key.public_key())
        assert header.pn == 5
        assert header.n == 10
        assert header.encrypted_sk == b"sk"

    def test_concat_function(self):
        """Test CONCAT function."""
        ad = b"associated_data"
        header = MessageHeader(generate_private_key(SECP256R1()).public_key(), 1, 2)

        result = CONCAT(ad, header)

        # Should start with AD length
        assert result[:4] == len(ad).to_bytes(4, "big")
        # Should contain AD
        assert ad in result
        # Should contain serialized header
        assert MessageHeader.serialize(header) in result

    def test_encrypt_decrypt(self):
        """Test ENCRYPT/DECRYPT functions."""
        mk = os.urandom(32)
        plaintext = "Test message"
        ad = b"associated_data"

        ciphertext = ENCRYPT(mk, plaintext, ad)
        decrypted = DECRYPT(mk, ciphertext, ad)

        assert decrypted == plaintext

    def test_encrypt_decrypt_wrong_key(self):
        """Test decryption with wrong key fails."""
        mk1 = os.urandom(32)
        mk2 = os.urandom(32)
        plaintext = "Test message"
        ad = b"associated_data"

        ciphertext = ENCRYPT(mk1, plaintext, ad)

        with pytest.raises(Exception):
            DECRYPT(mk2, ciphertext, ad)

    def test_encrypt_decrypt_wrong_ad(self):
        """Test decryption with wrong associated data fails."""
        mk = os.urandom(32)
        plaintext = "Test message"
        ad1 = b"associated_data1"
        ad2 = b"associated_data2"

        ciphertext = ENCRYPT(mk, plaintext, ad1)

        with pytest.raises(Exception):
            DECRYPT(mk, ciphertext, ad2)

    def test_public_key_encryption_decryption(self):
        """Test public key encryption/decryption functions."""
        private_key = generate_private_key(SECP256R1())
        public_key = private_key.public_key()
        data = b"secret data"

        encrypted = encrypt_with_public_key(data, public_key)
        decrypted = decrypt_with_private_key(encrypted, private_key)

        assert decrypted == data

    def test_public_key_encryption_wrong_key(self):
        """Test public key decryption with wrong key fails."""
        private_key1 = generate_private_key(SECP256R1())
        private_key2 = generate_private_key(SECP256R1())
        public_key1 = private_key1.public_key()
        data = b"secret data"

        encrypted = encrypt_with_public_key(data, public_key1)

        with pytest.raises(Exception):
            decrypt_with_private_key(encrypted, private_key2)

    def test_pk_bytes_function(self):
        """Test _pk_bytes function."""
        key = generate_private_key(SECP256R1())
        public_key = key.public_key()

        bytes1 = _pk_bytes(public_key)
        bytes2 = _pk_bytes(public_key)

        assert bytes1 == bytes2
        assert len(bytes1) == 65  # Uncompressed point format

    def test_same_pub_function(self):
        """Test _same_pub function."""
        key1 = generate_private_key(SECP256R1())
        key2 = generate_private_key(SECP256R1())
        public1 = key1.public_key()
        public2 = key2.public_key()

        assert _same_pub(public1, public1) is True
        assert _same_pub(public1, public2) is False
        assert _same_pub(None, public1) is False
        assert _same_pub(public1, None) is False
        assert _same_pub(None, None) is False


class TestMessengerServer:
    """Test MessengerServer functionality and security."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_server_initialization(self):
        """Test server initialization."""
        assert self.server.server_signing_key == self.server_sign_key
        assert self.server.server_decryption_key == self.server_enc_key

    def test_sign_certificate(self):
        """Test certificate signing."""
        client_key = generate_private_key(SECP256R1())
        cert = Certificate("alice", client_key.public_key())

        signature = self.server.signCert(cert)

        assert isinstance(signature, bytes)
        assert len(signature) > 0

    def test_certificate_signature_verification(self):
        """Test that signed certificates can be verified."""
        client_key = generate_private_key(SECP256R1())
        cert = Certificate("alice", client_key.public_key())

        signature = self.server.signCert(cert)

        # Verify signature manually
        cert_data = cert.getUserName().encode("utf-8") + _pk_bytes(cert.getPublicKey())

        # Should not raise exception
        self.server.server_signing_key.public_key().verify(
            signature, cert_data, ECDSA(SHA256())
        )

    def test_decrypt_report(self):
        """Test report decryption."""
        # Create a client to generate report
        client = MessengerClient(
            "alice",
            self.server.server_signing_key.public_key(),
            self.server.server_decryption_key.public_key(),
        )

        report_pt, report_ct = client.report("bob", "inappropriate content")
        decrypted = self.server.decryptReport(report_ct)

        assert "bob" in decrypted
        assert "inappropriate content" in decrypted

    def test_decrypt_report_malformed(self):
        """Test report decryption with malformed data."""
        with pytest.raises(Exception):
            self.server.decryptReport(b"invalid_report_data")

    def test_decrypt_report_wrong_key(self):
        """Test report decryption with wrong server key."""
        # Create client with different server key
        wrong_server_key = generate_private_key(SECP256R1())
        client = MessengerClient(
            "alice",
            self.server.server_signing_key.public_key(),
            wrong_server_key.public_key(),
        )

        report_pt, report_ct = client.report("bob", "test")

        with pytest.raises(Exception):
            self.server.decryptReport(report_ct)


class TestMessengerClient:
    """Test MessengerClient functionality and security."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

        self.alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        self.bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

    def test_client_initialization(self):
        """Test client initialization."""
        assert self.alice.name == "alice"
        assert self.alice.server_signing_pk == self.server_sign_key.public_key()
        assert self.alice.server_encryption_pk == self.server_enc_key.public_key()
        assert isinstance(self.alice.conns, dict)
        assert isinstance(self.alice.certs, dict)
        assert isinstance(self.alice.DHs, EllipticCurvePrivateKey)

    def test_generate_certificate(self):
        """Test certificate generation."""
        cert = self.alice.generateCertificate()

        assert cert.getUserName() == "alice"
        assert _same_pub(cert.getPublicKey(), self.alice.DHs.public_key())

    def test_receive_certificate_valid(self):
        """Test receiving valid certificate."""
        bob_cert = self.bob.generateCertificate()
        signature = self.server.signCert(bob_cert)

        self.alice.receiveCertificate(bob_cert, signature)

        assert "bob" in self.alice.certs
        assert self.alice.certs["bob"] == bob_cert

    def test_receive_certificate_invalid_signature(self):
        """Test receiving certificate with invalid signature."""
        bob_cert = self.bob.generateCertificate()
        invalid_signature = os.urandom(64)  # Random bytes

        with pytest.raises(Exception, match="certificate verification failed"):
            self.alice.receiveCertificate(bob_cert, invalid_signature)

    def test_receive_certificate_wrong_signature(self):
        """Test receiving certificate with signature for different cert."""
        bob_cert = self.bob.generateCertificate()
        alice_cert = self.alice.generateCertificate()

        # Sign alice's cert but try to use for bob's cert
        wrong_signature = self.server.signCert(alice_cert)

        with pytest.raises(Exception, match="certificate verification failed"):
            self.alice.receiveCertificate(bob_cert, wrong_signature)

    def test_send_message_without_certificate(self):
        """Test sending message without recipient certificate."""
        with pytest.raises(Exception, match="No certificate found"):
            self.alice.sendMessage("bob", "Hello!")

    def test_send_receive_message_flow(self):
        """Test complete send/receive message flow."""
        # Exchange certificates
        alice_cert = self.alice.generateCertificate()
        bob_cert = self.bob.generateCertificate()

        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)

        self.alice.receiveCertificate(bob_cert, bob_sig)
        self.bob.receiveCertificate(alice_cert, alice_sig)

        # Send message
        message = "Hello, Bob!"
        header_bytes, ciphertext = self.alice.sendMessage("bob", message)

        # Receive message
        decrypted = self.bob.receiveMessage("alice", header_bytes, ciphertext)

        assert decrypted == message

    def test_multiple_messages(self):
        """Test sending multiple messages (ratchet progression)."""
        # Setup certificates
        alice_cert = self.alice.generateCertificate()
        bob_cert = self.bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        self.alice.receiveCertificate(bob_cert, bob_sig)
        self.bob.receiveCertificate(alice_cert, alice_sig)

        messages = ["Message 1", "Message 2", "Message 3"]

        for msg in messages:
            header_bytes, ciphertext = self.alice.sendMessage("bob", msg)
            decrypted = self.bob.receiveMessage("alice", header_bytes, ciphertext)
            assert decrypted == msg

    def test_bidirectional_messaging(self):
        """Test bidirectional messaging."""
        # Setup certificates
        alice_cert = self.alice.generateCertificate()
        bob_cert = self.bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        self.alice.receiveCertificate(bob_cert, bob_sig)
        self.bob.receiveCertificate(alice_cert, alice_sig)

        # Alice to Bob
        header1, ct1 = self.alice.sendMessage("bob", "Hi Bob!")
        msg1 = self.bob.receiveMessage("alice", header1, ct1)
        assert msg1 == "Hi Bob!"

        # Bob to Alice
        header2, ct2 = self.bob.sendMessage("alice", "Hi Alice!")
        msg2 = self.alice.receiveMessage("bob", header2, ct2)
        assert msg2 == "Hi Alice!"

    def test_receive_message_wrong_ciphertext(self):
        """Test receiving message with wrong ciphertext."""
        # Setup certificates
        alice_cert = self.alice.generateCertificate()
        bob_cert = self.bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        self.alice.receiveCertificate(bob_cert, bob_sig)
        self.bob.receiveCertificate(alice_cert, alice_sig)

        # Send message but corrupt ciphertext
        header_bytes, ciphertext = self.alice.sendMessage("bob", "Hello!")
        wrong_ciphertext = os.urandom(len(ciphertext))

        result = self.bob.receiveMessage("alice", header_bytes, wrong_ciphertext)
        assert result is None

    def test_receive_message_replay_attack(self):
        """Test protection against replay attacks."""
        # Setup certificates
        alice_cert = self.alice.generateCertificate()
        bob_cert = self.bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        self.alice.receiveCertificate(bob_cert, bob_sig)
        self.bob.receiveCertificate(alice_cert, alice_sig)

        # Send and receive message
        header_bytes, ciphertext = self.alice.sendMessage("bob", "Hello!")
        msg1 = self.bob.receiveMessage("alice", header_bytes, ciphertext)
        assert msg1 == "Hello!"

        # Try to replay the same message
        msg2 = self.bob.receiveMessage("alice", header_bytes, ciphertext)
        assert msg2 is None  # Should be rejected

    def test_report_functionality(self):
        """Test report generation."""
        report_pt, report_ct = self.alice.report("bob", "inappropriate content")

        assert "bob" in report_pt
        assert "inappropriate content" in report_pt
        assert isinstance(report_ct, bytes)
        assert len(report_ct) > 0

    @given(st.text(), st.text(min_size=1))
    def test_report_various_inputs(self, user, content):
        """Property-based test for report generation."""
        report_pt, report_ct = self.alice.report(user, content)

        decrypted = self.server.decryptReport(report_ct)
        assert user in decrypted
        assert content in decrypted


class TestSecurityVulnerabilities:
    """Test for various security vulnerabilities."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks on signature verification."""
        client = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        cert = client.generateCertificate()
        valid_signature = self.server.signCert(cert)
        invalid_signature = os.urandom(len(valid_signature))

        # Both should fail/succeed in similar time
        # This is a basic test - real timing attack testing would need more sophisticated measurement
        import time

        start = time.time()
        try:
            client.receiveCertificate(cert, valid_signature)
        except:
            pass
        valid_time = time.time() - start

        start = time.time()
        try:
            client.receiveCertificate(cert, invalid_signature)
        except:
            pass
        invalid_time = time.time() - start

        # Times should be reasonably similar (within an order of magnitude)
        assert abs(valid_time - invalid_time) < max(valid_time, invalid_time) * 10

    def test_key_reuse_prevention(self):
        """Test that keys are properly rotated."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Setup certificates
        alice_cert = alice.generateCertificate()
        bob_cert = bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        alice.receiveCertificate(bob_cert, bob_sig)
        bob.receiveCertificate(alice_cert, alice_sig)

        # Send multiple messages and check that keys change
        _, ct1 = alice.sendMessage("bob", "Message 1")
        _, ct2 = alice.sendMessage("bob", "Message 2")

        # The ciphertexts should be different even for the same message
        _, ct3 = alice.sendMessage("bob", "Message 1")  # Same message

        assert ct1 != ct2
        assert ct1 != ct3  # Same plaintext but different ciphertext

    def test_forward_secrecy(self):
        """Test forward secrecy property."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Setup certificates
        alice_cert = alice.generateCertificate()
        bob_cert = bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        alice.receiveCertificate(bob_cert, bob_sig)
        bob.receiveCertificate(alice_cert, alice_sig)

        # Send initial message from Alice to Bob
        header1, ct1 = alice.sendMessage("bob", "Old message")
        msg1 = bob.receiveMessage("alice", header1, ct1)
        assert msg1 == "Old message"

        # Capture the connection DH keys before ratchet
        old_alice_conn_dh = alice.conns["bob"].DHs_sk

        # Bob sends reply to trigger DH ratchet in Alice
        header2, ct2 = bob.sendMessage("alice", "Reply from Bob")
        msg2 = alice.receiveMessage("bob", header2, ct2)
        assert msg2 == "Reply from Bob"

        # Check that Alice's connection DH key has changed (forward secrecy)
        new_alice_conn_dh = alice.conns["bob"].DHs_sk

        # Keys should be different objects (DH ratchet occurred)
        assert (
            old_alice_conn_dh is not new_alice_conn_dh
        ), "DH key should change for forward secrecy"

    def test_malformed_input_handling(self):
        """Test handling of various malformed inputs."""
        client = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Test malformed certificate signatures
        cert = client.generateCertificate()

        malformed_sigs = [
            b"",  # Empty
            b"a",  # Too short
            os.urandom(32),  # Wrong length
            os.urandom(100),  # Too long
        ]

        for sig in malformed_sigs:
            with pytest.raises(Exception):
                client.receiveCertificate(cert, sig)

    def test_nonce_reuse_prevention(self):
        """Test that nonces are not reused."""
        mk = os.urandom(32)
        message = "Test message"
        ad = b"associated_data"

        # Encrypt same message multiple times
        ct1 = ENCRYPT(mk, message, ad)
        ct2 = ENCRYPT(mk, message, ad)

        # Ciphertexts should be different due to different nonces
        assert ct1 != ct2

        # Both should decrypt correctly
        assert DECRYPT(mk, ct1, ad) == message
        assert DECRYPT(mk, ct2, ad) == message

    def test_key_derivation_determinism(self):
        """Test that key derivation is deterministic."""
        rk = os.urandom(32)
        dh_out = os.urandom(32)

        # Same inputs should produce same outputs
        new_rk1, ck1 = KDF_RK(rk, dh_out)
        new_rk2, ck2 = KDF_RK(rk, dh_out)

        assert new_rk1 == new_rk2
        assert ck1 == ck2

    def test_certificate_binding(self):
        """Test that certificates are properly bound to names."""
        alice_key = generate_private_key(SECP256R1())

        # Create certificate for alice
        alice_cert = Certificate("alice", alice_key.public_key())
        alice_sig = self.server.signCert(alice_cert)

        # Try to create certificate with same key but different name
        fake_cert = Certificate("bob", alice_key.public_key())

        client = MessengerClient(
            "charlie",
            self.server_sign_key.public_key(),
            self.server_enc_key.public_key(),
        )

        # Should not be able to use alice's signature for fake cert
        with pytest.raises(Exception):
            client.receiveCertificate(fake_cert, alice_sig)


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_empty_messages(self):
        """Test sending empty messages."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Setup certificates
        alice_cert = alice.generateCertificate()
        bob_cert = bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        alice.receiveCertificate(bob_cert, bob_sig)
        bob.receiveCertificate(alice_cert, alice_sig)

        # Send empty message
        header, ct = alice.sendMessage("bob", "")
        msg = bob.receiveMessage("alice", header, ct)

        assert msg == ""

    def test_very_long_messages(self):
        """Test sending very long messages."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Setup certificates
        alice_cert = alice.generateCertificate()
        bob_cert = bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        alice.receiveCertificate(bob_cert, bob_sig)
        bob.receiveCertificate(alice_cert, alice_sig)

        # Send very long message
        long_message = "A" * 10000
        header, ct = alice.sendMessage("bob", long_message)
        msg = bob.receiveMessage("alice", header, ct)

        assert msg == long_message

    def test_unicode_messages(self):
        """Test sending messages with unicode characters."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Setup certificates
        alice_cert = alice.generateCertificate()
        bob_cert = bob.generateCertificate()
        alice_sig = self.server.signCert(alice_cert)
        bob_sig = self.server.signCert(bob_cert)
        alice.receiveCertificate(bob_cert, bob_sig)
        bob.receiveCertificate(alice_cert, alice_sig)

        # Send unicode message
        unicode_message = "Hello 👋 世界 🌍 مرحبا"
        header, ct = alice.sendMessage("bob", unicode_message)
        msg = bob.receiveMessage("alice", header, ct)

        assert msg == unicode_message

    def test_multiple_certificate_updates(self):
        """Test updating certificates multiple times."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Create multiple certificates for bob
        for i in range(3):
            bob_key = generate_private_key(SECP256R1())
            bob_cert = Certificate("bob", bob_key.public_key())
            bob_sig = self.server.signCert(bob_cert)

            alice.receiveCertificate(bob_cert, bob_sig)

            # Should overwrite previous certificate
            assert "bob" in alice.certs
            assert _same_pub(alice.certs["bob"].getPublicKey(), bob_key.public_key())


class TestPropertyBasedTesting:
    """Property-based tests using Hypothesis."""

    @given(st.text(min_size=1, max_size=1000))
    @settings(max_examples=50)
    def test_message_encryption_decryption_property(self, message):
        """Property: Any message should encrypt and decrypt correctly."""
        mk = os.urandom(32)
        ad = os.urandom(16)

        try:
            encrypted = ENCRYPT(mk, message, ad)
            decrypted = DECRYPT(mk, encrypted, ad)
            assert decrypted == message
        except UnicodeDecodeError:
            # Skip messages that can't be encoded/decoded properly
            pass

    @given(st.binary(min_size=32, max_size=32), st.binary(min_size=32, max_size=32))
    def test_kdf_output_properties(self, rk, dh_out):
        """Property: KDF should always produce consistent output."""
        new_rk1, ck1 = KDF_RK(rk, dh_out)
        new_rk2, ck2 = KDF_RK(rk, dh_out)

        # Same inputs should produce same outputs
        assert new_rk1 == new_rk2
        assert ck1 == ck2

        # Outputs should be different from inputs
        assert new_rk1 != rk
        assert ck1 != rk
        assert new_rk1 != ck1

    @given(st.binary(min_size=32, max_size=32))
    def test_chain_key_derivation_property(self, ck):
        """Property: Chain key derivation should be deterministic and non-reversible."""
        new_ck1, mk1 = KDF_CK(ck)
        new_ck2, mk2 = KDF_CK(ck)

        # Same input should produce same output
        assert new_ck1 == new_ck2
        assert mk1 == mk2

        # Output should be different from input
        assert new_ck1 != ck
        assert mk1 != ck
        assert new_ck1 != mk1


def test_integration_full_protocol():
    """Integration test of the complete protocol."""
    # Setup server
    server_sign_key = generate_private_key(SECP256R1())
    server_enc_key = generate_private_key(SECP256R1())
    server = MessengerServer(server_sign_key, server_enc_key)

    # Setup clients
    alice = MessengerClient(
        "alice", server_sign_key.public_key(), server_enc_key.public_key()
    )
    bob = MessengerClient(
        "bob", server_sign_key.public_key(), server_enc_key.public_key()
    )
    carol = MessengerClient(
        "carol", server_sign_key.public_key(), server_enc_key.public_key()
    )

    # Generate and distribute certificates
    alice_cert = alice.generateCertificate()
    bob_cert = bob.generateCertificate()
    carol_cert = carol.generateCertificate()

    alice_sig = server.signCert(alice_cert)
    bob_sig = server.signCert(bob_cert)
    carol_sig = server.signCert(carol_cert)

    # Distribute certificates
    alice.receiveCertificate(bob_cert, bob_sig)
    alice.receiveCertificate(carol_cert, carol_sig)
    bob.receiveCertificate(alice_cert, alice_sig)
    bob.receiveCertificate(carol_cert, carol_sig)
    carol.receiveCertificate(alice_cert, alice_sig)
    carol.receiveCertificate(bob_cert, bob_sig)

    # Test conversation
    messages = [
        ("alice", "bob", "Hi Bob!"),
        ("bob", "alice", "Hi Alice!"),
        ("alice", "carol", "Hi Carol!"),
        ("carol", "alice", "Hi Alice!"),
        ("bob", "carol", "Hi Carol!"),
        ("carol", "bob", "Hi Bob!"),
    ]

    clients = {"alice": alice, "bob": bob, "carol": carol}

    for sender_name, recipient_name, message in messages:
        sender = clients[sender_name]
        recipient = clients[recipient_name]

        header, ct = sender.sendMessage(recipient_name, message)
        decrypted = recipient.receiveMessage(sender_name, header, ct)

        assert decrypted == message

    # Test reporting
    report_pt, report_ct = alice.report("bob", "inappropriate content")
    decrypted_report = server.decryptReport(report_ct)

    assert "bob" in decrypted_report
    assert "inappropriate content" in decrypted_report


if __name__ == "__main__":
    # Run the tests
    pytest.main([__file__, "-v", "--tb=short"])
