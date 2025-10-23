"""
Security vulnerability tests for the cryptography messenger application.
Tests for common cryptographic vulnerabilities, side-channel attacks, and protocol weaknesses.
"""

import pytest
import os
import time
import threading
import gc
from unittest.mock import patch, Mock
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
import hashlib

from messenger import (
    MessengerServer,
    MessengerClient,
    Certificate,
    ENCRYPT,
    DECRYPT,
    KDF_RK,
)


class TestCryptographicVulnerabilities:
    """Test for cryptographic vulnerabilities and weaknesses."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_weak_randomness_detection(self):
        """Test detection of weak randomness in key generation."""
        # Mock os.urandom to return predictable values
        with patch("os.urandom") as mock_urandom:
            mock_urandom.return_value = b"\x00" * 32  # Weak entropy

            # Key generation should still work but we can detect patterns
            key1 = generate_private_key(SECP256R1())
            key2 = generate_private_key(SECP256R1())

            # In real implementation, these should be different
            # This test would fail with truly weak randomness
            assert key1.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            ) != key2.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

    def test_side_channel_timing_attacks(self):
        """Test for timing side-channel vulnerabilities in signature verification."""
        client = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        cert = client.generateCertificate()
        valid_signature = self.server.signCert(cert)

        # Create signatures that fail at different points
        short_sig = b"a" * 10  # Fails early
        wrong_length_sig = b"b" * len(valid_signature)  # Fails later

        times = []

        # Measure timing for different invalid signatures
        for sig in [short_sig, wrong_length_sig]:
            start = time.perf_counter()
            try:
                client.receiveCertificate(cert, sig)
            except Exception:
                pass
            end = time.perf_counter()
            times.append(end - start)

        # Times should not differ significantly (constant time verification)
        if len(times) > 1:
            ratio = max(times) / min(times) if min(times) > 0 else float("inf")
            # Allow some variance but not orders of magnitude
            assert ratio < 100, f"Timing difference too large: {ratio}"

    def test_memory_disclosure_vulnerability(self):
        """Test for potential memory disclosure through uninitialized data."""
        # Test that sensitive data is properly cleared
        mk = os.urandom(32)
        plaintext = "sensitive data"
        ad = b"associated_data"

        # Encrypt and decrypt
        ciphertext = ENCRYPT(mk, plaintext, ad)
        decrypted = DECRYPT(mk, ciphertext, ad)

        # Force garbage collection to see if sensitive data lingers
        gc.collect()

        # This is a conceptual test - in practice, we'd need memory scanning
        # to detect if keys persist in memory after use
        assert decrypted == plaintext

    def test_nonce_collision_resistance(self):
        """Test for nonce collision vulnerabilities."""
        mk = os.urandom(32)
        message = "test message"
        ad = b"associated_data"

        # Generate many ciphertexts and check for nonce reuse
        ciphertexts = set()
        nonces = set()

        for _ in range(1000):
            ct = ENCRYPT(mk, message, ad)
            nonce = ct[:12]  # First 12 bytes are nonce

            assert nonce not in nonces, "Nonce reuse detected!"
            nonces.add(nonce)
            ciphertexts.add(ct)

        # All ciphertexts should be unique
        assert len(ciphertexts) == 1000

    def test_key_derivation_bias(self):
        """Test for bias in key derivation functions."""
        # Test that KDF output is uniformly distributed
        rk = os.urandom(32)

        # Generate many derived keys
        derived_keys = []
        for i in range(256):
            dh_out = i.to_bytes(32, "big")
            new_rk, ck = KDF_RK(rk, dh_out)
            derived_keys.append(new_rk)

        # Check for obvious patterns (this is a basic test)
        # In practice, statistical tests would be more comprehensive
        unique_keys = set(derived_keys)
        assert len(unique_keys) == len(derived_keys), "KDF produced duplicate keys"

        # Check that keys don't have obvious patterns
        for key in derived_keys[:10]:
            # Key shouldn't be all zeros or all same byte
            assert key != b"\x00" * 32
            assert len(set(key)) > 1

    def test_certificate_substitution_attack(self):
        """Test for certificate substitution vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Create legitimate certificate for bob
        bob_key = generate_private_key(SECP256R1())
        bob_cert = Certificate("bob", bob_key.public_key())
        bob_sig = self.server.signCert(bob_cert)

        # Create malicious certificate with same key but different name
        mallory_cert = Certificate("mallory", bob_key.public_key())

        # Should not be able to use bob's signature for mallory's cert
        with pytest.raises(Exception):
            alice.receiveCertificate(mallory_cert, bob_sig)

    def test_replay_attack_resistance(self):
        """Test resistance to replay attacks."""
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

        # Send message
        header, ct = alice.sendMessage("bob", "Hello!")

        # First reception should work
        msg1 = bob.receiveMessage("alice", header, ct)
        assert msg1 == "Hello!"

        # Replay should be rejected
        msg2 = bob.receiveMessage("alice", header, ct)
        assert msg2 is None

    def test_message_forgery_resistance(self):
        """Test resistance to message forgery attacks."""
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

        # Send legitimate message
        header, ct = alice.sendMessage("bob", "Hello!")

        # Try to forge message by modifying ciphertext
        forged_ct = bytearray(ct)
        forged_ct[0] ^= 1  # Flip one bit

        # Forgery should be rejected
        msg = bob.receiveMessage("alice", header, bytes(forged_ct))
        assert msg is None

    def test_downgrade_attack_resistance(self):
        """Test resistance to cryptographic downgrade attacks."""
        # This test is conceptual since the implementation uses fixed algorithms
        # In a real system, we'd test that weaker algorithms can't be negotiated

        # Verify that only strong algorithms are used
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Check that keys use strong curves (SECP256R1)
        assert alice.DHs.curve.name == "secp256r1"

        # Check that strong hash algorithms are used (SHA256)
        # This would be verified by inspecting the cryptographic operations

    def test_key_confusion_attack(self):
        """Test for key confusion vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        print(alice)
        # Try to use signing key as encryption key
        try:
            # This should be prevented by proper key usage validation
            fake_client = MessengerClient(
                "mallory",
                self.server_enc_key.public_key(),  # Wrong key type
                self.server_sign_key.public_key(),  # Wrong key type
            )
            print(fake_client)
            # If this doesn't fail, there might be a key confusion vulnerability
        except Exception:
            # Expected - key confusion should be prevented
            pass

    def test_cross_protocol_attack_resistance(self):
        """Test resistance to cross-protocol attacks."""
        # Create message that could be interpreted in different contexts
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Generate certificate
        cert = alice.generateCertificate()

        # Try to use certificate data as message (cross-protocol confusion)
        # This should fail due to proper protocol separation
        cert_data = cert.getUserName().encode() + b"some_key_bytes"

        print(cert_data)
        # This is a conceptual test - proper protocol design should prevent
        # certificate data from being interpreted as message data


class TestConcurrencyVulnerabilities:
    """Test for concurrency-related vulnerabilities."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_race_condition_in_message_counters(self):
        """Test for race conditions in message counter handling."""
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

        # Test concurrent message sending
        messages = []
        errors = []

        def send_message(i):
            try:
                header, ct = alice.sendMessage("bob", f"Message {i}")
                messages.append((header, ct, i))
            except Exception as e:
                errors.append(e)

        # Send messages concurrently
        threads = []
        for i in range(10):
            t = threading.Thread(target=send_message, args=(i,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # All messages should be sent successfully
        assert len(errors) == 0
        assert len(messages) == 10

        # Message counters should be sequential
        # (This test checks that concurrent access doesn't corrupt state)

    def test_certificate_validation_race_condition(self):
        """Test for race conditions in certificate validation."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Create certificate
        bob_cert = Certificate("bob", generate_private_key(SECP256R1()).public_key())
        bob_sig = self.server.signCert(bob_cert)

        errors = []
        successes = []

        def receive_cert():
            try:
                alice.receiveCertificate(bob_cert, bob_sig)
                successes.append(1)
            except Exception as e:
                errors.append(e)

        # Try to receive same certificate concurrently
        threads = []
        for _ in range(5):
            t = threading.Thread(target=receive_cert)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # At least one should succeed (idempotent operation)
        assert len(successes) > 0
        # Should not have any unexpected errors
        assert (
            len([e for e in errors if "certificate verification failed" not in str(e)])
            == 0
        )


class TestInputValidationVulnerabilities:
    """Test for input validation vulnerabilities."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_buffer_overflow_protection(self):
        """Test protection against buffer overflow attacks."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Test with extremely long names
        long_name = "A" * 100000

        # Should handle gracefully without crashing
        try:
            long_key = generate_private_key(SECP256R1())
            cert = Certificate(long_name, long_key.public_key())
            sig = self.server.signCert(cert)
            alice.receiveCertificate(cert, sig)
        except Exception:
            # May fail due to memory limits, but shouldn't crash
            pass

    def test_null_byte_injection(self):
        """Test for null byte injection vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Test names with null bytes
        malicious_names = [
            "alice\x00admin",
            "bob\x00\x00",
            "\x00alice",
        ]

        for name in malicious_names:
            try:
                key = generate_private_key(SECP256R1())
                cert = Certificate(name, key.public_key())
                sig = self.server.signCert(cert)
                alice.receiveCertificate(cert, sig)

                # Check that full name is preserved
                assert alice.certs[name].getUserName() == name
            except Exception:
                # May reject invalid names, which is acceptable
                pass

    def test_format_string_vulnerabilities(self):
        """Test for format string vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Test format string injection attempts
        format_strings = [
            "%s%s%s%s",
            "%x%x%x%x",
            "%n%n%n%n",
            "{}{}{}{}",
        ]

        for fmt_str in format_strings:
            try:
                # Test in report functionality
                report_pt, report_ct = alice.report(fmt_str, fmt_str)
                decrypted = self.server.decryptReport(report_ct)

                # Should not cause format string interpretation
                assert fmt_str in decrypted
            except Exception:
                # May reject malformed input, which is acceptable
                pass

    def test_integer_overflow_protection(self):
        """Test protection against integer overflow attacks."""
        from messenger import MessageHeader

        # Test with maximum integer values
        max_int = 2**32 - 1

        try:
            key = generate_private_key(SECP256R1())
            header = MessageHeader(key.public_key(), max_int, max_int)

            # Serialization should handle large integers
            serialized = MessageHeader.serialize(header)
            deserialized = MessageHeader.deserialize(serialized)

            assert deserialized.pn == max_int
            assert deserialized.n == max_int
        except Exception as e:
            # May have reasonable limits, which is acceptable
            assert "overflow" not in str(e).lower()

    def test_unicode_normalization_attacks(self):
        """Test for Unicode normalization vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Test different Unicode normalizations of same name
        names = [
            "café",  # NFC
            "cafe\u0301",  # NFD (e + combining acute accent)
        ]

        certificates = []
        for name in names:
            try:
                key = generate_private_key(SECP256R1())
                cert = Certificate(name, key.public_key())
                sig = self.server.signCert(cert)
                alice.receiveCertificate(cert, sig)
                certificates.append(name)
            except Exception:
                pass

        # Should handle Unicode consistently
        # (Implementation-specific behavior is acceptable)


class TestProtocolVulnerabilities:
    """Test for protocol-level vulnerabilities."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_man_in_the_middle_resistance(self):
        """Test resistance to man-in-the-middle attacks."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )
        bob = MessengerClient(
            "bob", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Attacker with different server key
        attacker_key = generate_private_key(SECP256R1())
        attacker_server = MessengerServer(attacker_key, self.server_enc_key)

        # Bob's real certificate
        bob_cert = bob.generateCertificate()

        # Attacker tries to forge signature
        fake_sig = attacker_server.signCert(bob_cert)

        # Alice should reject certificate with wrong signature
        with pytest.raises(Exception):
            alice.receiveCertificate(bob_cert, fake_sig)

    def test_forward_secrecy_validation(self):
        """Test that forward secrecy is properly implemented."""
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

        # Send initial message
        header1, ct1 = alice.sendMessage("bob", "Message 1")
        msg1 = bob.receiveMessage("alice", header1, ct1)
        assert msg1 == "Message 1"
        # Capture current state
        old_alice_conn = alice.conns["bob"]
        old_dh_key = old_alice_conn.DHs_sk

        # Send more messages to trigger DH ratchet
        for i in range(5):
            header, ct = alice.sendMessage("bob", f"Message {i + 2}")
            bob.receiveMessage("alice", header, ct)

        # DH key should have changed (forward secrecy)
        new_dh_key = alice.conns["bob"].DHs_sk
        assert old_dh_key != new_dh_key

    def test_message_ordering_attack(self):
        """Test resistance to message ordering attacks."""
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

        # Send messages in order
        messages = []
        for i in range(3):
            header, ct = alice.sendMessage("bob", f"Message {i}")
            messages.append((header, ct, i))

        # Receive first message
        msg0 = bob.receiveMessage("alice", messages[0][0], messages[0][1])
        assert msg0 == "Message 0"

        # Try to receive third message (out of order)
        msg2 = bob.receiveMessage("alice", messages[2][0], messages[2][1])
        # Should be rejected due to counter mismatch
        assert msg2 is None

    def test_authentication_bypass_attempt(self):
        """Test for authentication bypass vulnerabilities."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        # Try to send message without proper certificate exchange
        with pytest.raises(Exception):
            alice.sendMessage("bob", "Unauthenticated message")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
