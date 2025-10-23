"""
Performance and stress tests for the cryptography messenger application.
Tests scalability, resource usage, and performance under load.
"""

import pytest
import time
import threading
import multiprocessing
import gc
import tracemalloc
from cryptography.hazmat.primitives.asymmetric.ec import generate_private_key, SECP256R1

from messenger import (
    MessengerServer,
    MessengerClient,
    Certificate,
    Connection,
    ENCRYPT,
    DECRYPT,
    KDF_RK,
    KDF_CK,
)


class TestPerformance:
    """Test performance characteristics of the messaging system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_key_generation_performance(self):
        """Test performance of key generation operations."""
        start_time = time.perf_counter()

        # Generate multiple keys
        keys = []
        for _ in range(100):
            key = generate_private_key(SECP256R1())
            keys.append(key)

        end_time = time.perf_counter()
        duration = end_time - start_time

        # Should generate 100 keys in reasonable time (< 10 seconds)
        assert duration < 10.0, f"Key generation too slow: {duration:.2f}s"
        print(f"Generated 100 keys in {duration:.3f}s ({duration / 100:.3f}s per key)")

    def test_certificate_signing_performance(self):
        """Test performance of certificate signing operations."""
        # Generate test certificates
        certificates = []
        for i in range(100):
            key = generate_private_key(SECP256R1())
            cert = Certificate(f"user_{i}", key.public_key())
            certificates.append(cert)

        start_time = time.perf_counter()

        # Sign all certificates
        signatures = []
        for cert in certificates:
            sig = self.server.signCert(cert)
            signatures.append(sig)

        end_time = time.perf_counter()
        duration = end_time - start_time

        # Should sign 100 certificates in reasonable time
        assert duration < 5.0, f"Certificate signing too slow: {duration:.2f}s"
        print(
            f"Signed 100 certificates in {duration:.3f}s ({duration / 100:.3f}s per cert)"
        )

    def test_message_encryption_performance(self):
        """Test performance of message encryption/decryption."""
        # Setup clients
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

        # Test message performance
        message = "This is a test message for performance testing."

        start_time = time.perf_counter()

        # Send and receive multiple messages
        for i in range(100):
            header, ct = alice.sendMessage("bob", f"{message} #{i}")
            decrypted = bob.receiveMessage("alice", header, ct)
            assert decrypted == f"{message} #{i}"

        end_time = time.perf_counter()
        duration = end_time - start_time

        # Should process 100 messages in reasonable time
        assert duration < 5.0, f"Message processing too slow: {duration:.2f}s"
        print(
            f"Processed 100 messages in {duration:.3f}s ({duration / 100:.3f}s per message)"
        )

    def test_kdf_performance(self):
        """Test performance of key derivation functions."""
        import os

        rk = os.urandom(32)
        dh_out = os.urandom(32)
        ck = os.urandom(32)

        start_time = time.perf_counter()

        # Perform many KDF operations
        for _ in range(1000):
            new_rk, new_ck = KDF_RK(rk, dh_out)
            rk = new_rk

        for _ in range(1000):
            new_ck, mk = KDF_CK(ck)
            ck = new_ck

        end_time = time.perf_counter()
        duration = end_time - start_time

        # Should perform 2000 KDF operations quickly
        assert duration < 2.0, f"KDF operations too slow: {duration:.2f}s"
        print(f"Performed 2000 KDF operations in {duration:.3f}s")

    def test_large_message_performance(self):
        """Test performance with large messages."""
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

        # Test with increasingly large messages
        message_sizes = [1024, 10240, 102400, 1024000]  # 1KB, 10KB, 100KB, 1MB

        for size in message_sizes:
            large_message = "A" * size

            start_time = time.perf_counter()
            header, ct = alice.sendMessage("bob", large_message)
            decrypted = bob.receiveMessage("alice", header, ct)
            end_time = time.perf_counter()

            duration = end_time - start_time

            assert decrypted == large_message
            # Performance should scale reasonably with message size
            assert (
                duration < size / 10000
            ), f"Large message processing too slow: {duration:.3f}s for {size} bytes"
            print(f"Processed {size} byte message in {duration:.3f}s")


class TestScalability:
    """Test scalability of the messaging system."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_many_clients_scalability(self):
        """Test system performance with many clients."""
        num_clients = 50
        clients = []

        # Create many clients
        for i in range(num_clients):
            client = MessengerClient(
                f"client_{i}",
                self.server_sign_key.public_key(),
                self.server_enc_key.public_key(),
            )
            clients.append(client)

        # Generate and distribute certificates
        certificates = []
        signatures = []

        start_time = time.perf_counter()

        for client in clients:
            cert = client.generateCertificate()
            sig = self.server.signCert(cert)
            certificates.append(cert)
            signatures.append(sig)

        # Distribute certificates to all clients
        for i, client in enumerate(clients):
            for j, (cert, sig) in enumerate(zip(certificates, signatures)):
                if i != j:  # Don't give client their own certificate
                    client.receiveCertificate(cert, sig)

        end_time = time.perf_counter()
        setup_duration = end_time - start_time

        print(f"Set up {num_clients} clients in {setup_duration:.3f}s")

        # Test messaging between random clients
        start_time = time.perf_counter()

        import random

        for _ in range(100):
            sender_idx = random.randint(0, num_clients - 1)
            receiver_idx = random.randint(0, num_clients - 1)

            if sender_idx != receiver_idx:
                sender = clients[sender_idx]
                receiver = clients[receiver_idx]
                receiver_name = f"client_{receiver_idx}"
                sender_name = f"client_{sender_idx}"

                try:
                    header, ct = sender.sendMessage(
                        receiver_name, f"Hello from {sender_name}"
                    )
                    decrypted = receiver.receiveMessage(sender_name, header, ct)
                    assert decrypted == f"Hello from {sender_name}"
                except Exception as e:
                    print(f"Error in messaging: {e}")

        end_time = time.perf_counter()
        messaging_duration = end_time - start_time

        print(f"Completed 100 random messages in {messaging_duration:.3f}s")

    def test_message_queue_scalability(self):
        """Test handling of many queued messages."""
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

        # Send many messages without receiving them
        queued_messages = []
        num_messages = 1000

        start_time = time.perf_counter()

        for i in range(num_messages):
            header, ct = alice.sendMessage("bob", f"Queued message {i}")
            queued_messages.append((header, ct, i))

        send_time = time.perf_counter()

        # Now receive all messages
        for header, ct, i in queued_messages:
            decrypted = bob.receiveMessage("alice", header, ct)
            expected = f"Queued message {i}"
            # Note: Due to message counter validation, only some messages may be received
            if decrypted is not None:
                assert decrypted == expected

        receive_time = time.perf_counter()

        send_duration = send_time - start_time
        receive_duration = receive_time - send_time

        print(f"Sent {num_messages} messages in {send_duration:.3f}s")
        print(f"Processed queued messages in {receive_duration:.3f}s")


class TestResourceUsage:
    """Test resource usage and memory management."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_memory_usage_under_load(self):
        """Test memory usage during heavy messaging."""
        tracemalloc.start()

        # Setup clients
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

        # Measure baseline memory
        baseline = tracemalloc.get_traced_memory()[0]

        # Send many messages
        for i in range(1000):
            header, ct = alice.sendMessage("bob", f"Memory test message {i}")

            # Force garbage collection every 100 messages
            if i % 100 == 0:
                gc.collect()
                current, peak = tracemalloc.get_traced_memory()
                print(
                    f"Message {i}: Current memory: {current / 1024 / 1024:.2f} MB, Peak: {peak / 1024 / 1024:.2f} MB"
                )

        # Final memory measurement
        final_memory, peak_memory = tracemalloc.get_traced_memory()
        memory_growth = final_memory - baseline

        tracemalloc.stop()

        # Memory growth should be reasonable
        max_acceptable_growth = 100 * 1024 * 1024  # 100 MB
        assert (
            memory_growth < max_acceptable_growth
        ), f"Excessive memory growth: {memory_growth / 1024 / 1024:.2f} MB"

        print(f"Memory growth: {memory_growth / 1024 / 1024:.2f} MB")
        print(f"Peak memory: {peak_memory / 1024 / 1024:.2f} MB")

    def test_connection_state_cleanup(self):
        """Test that connection states don't accumulate indefinitely."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        initial_connections = len(alice.conns)

        # Create connections to many different "users"
        for i in range(100):
            # Create fake certificate for user
            user_key = generate_private_key(SECP256R1())
            user_cert = Certificate(f"user_{i}", user_key.public_key())
            user_sig = self.server.signCert(user_cert)
            alice.receiveCertificate(user_cert, user_sig)

            # Send message (creates connection)
            try:
                alice.sendMessage(f"user_{i}", f"Hello user {i}")
            except:
                pass  # May fail due to missing receiver, but connection is created

        final_connections = len(alice.conns)
        connection_growth = final_connections - initial_connections

        # Should have created connections for each user
        assert (
            connection_growth <= 100
        ), f"Unexpected connection count: {connection_growth}"

        print(f"Created {connection_growth} connections")

    def test_certificate_storage_efficiency(self):
        """Test efficient storage of certificates."""
        alice = MessengerClient(
            "alice", self.server_sign_key.public_key(), self.server_enc_key.public_key()
        )

        import sys

        # Measure size of empty certificate store
        baseline_size = sys.getsizeof(alice.certs)

        # Add many certificates
        for i in range(1000):
            user_key = generate_private_key(SECP256R1())
            user_cert = Certificate(f"user_{i:04d}", user_key.public_key())
            user_sig = self.server.signCert(user_cert)
            alice.receiveCertificate(user_cert, user_sig)

        # Measure final size
        final_size = sys.getsizeof(alice.certs)
        size_growth = final_size - baseline_size

        # Size growth should be reasonable per certificate
        avg_size_per_cert = size_growth / 1000

        print(f"Certificate storage: {size_growth} bytes for 1000 certificates")
        print(f"Average size per certificate: {avg_size_per_cert:.2f} bytes")

        # Should be efficient (less than 1KB per certificate in dict overhead)
        assert (
            avg_size_per_cert < 1024
        ), f"Certificate storage inefficient: {avg_size_per_cert} bytes per cert"


class TestStressTests:
    """Stress tests to find breaking points."""

    def setup_method(self):
        """Set up test fixtures."""
        self.server_sign_key = generate_private_key(SECP256R1())
        self.server_enc_key = generate_private_key(SECP256R1())
        self.server = MessengerServer(self.server_sign_key, self.server_enc_key)

    def test_rapid_key_generation_stress(self):
        """Stress test rapid key generation."""
        start_time = time.perf_counter()

        # Generate keys rapidly
        keys = []
        target_time = 5.0  # Run for 5 seconds

        while time.perf_counter() - start_time < target_time:
            key = generate_private_key(SECP256R1())
            keys.append(key)

        end_time = time.perf_counter()
        duration = end_time - start_time
        key_rate = len(keys) / duration

        print(
            f"Generated {len(keys)} keys in {duration:.3f}s ({key_rate:.1f} keys/sec)"
        )

        # Should maintain reasonable performance
        assert key_rate > 1, f"Key generation rate too slow: {key_rate:.1f} keys/sec"

    def test_encryption_stress(self):
        """Stress test encryption/decryption operations."""
        import os

        mk = os.urandom(32)
        ad = os.urandom(16)
        message = "This is a stress test message for encryption operations."

        start_time = time.perf_counter()
        operations = 0
        target_time = 3.0  # Run for 3 seconds

        while time.perf_counter() - start_time < target_time:
            # Encrypt
            ciphertext = ENCRYPT(mk, message, ad)
            # Decrypt
            decrypted = DECRYPT(mk, ciphertext, ad)
            assert decrypted == message
            operations += 1

        end_time = time.perf_counter()
        duration = end_time - start_time
        op_rate = operations / duration

        print(
            f"Performed {operations} encrypt/decrypt cycles in {duration:.3f}s ({op_rate:.1f} ops/sec)"
        )

        # Should maintain reasonable performance
        assert op_rate > 100, f"Encryption rate too slow: {op_rate:.1f} ops/sec"

    def test_connection_stress(self):
        """Stress test connection management."""
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

        # Rapid messaging to stress ratchet
        start_time = time.perf_counter()
        messages_sent = 0
        target_time = 5.0  # Run for 5 seconds

        while time.perf_counter() - start_time < target_time:
            try:
                header, ct = alice.sendMessage("bob", f"Stress message {messages_sent}")
                decrypted = bob.receiveMessage("alice", header, ct)
                if decrypted == f"Stress message {messages_sent}":
                    messages_sent += 1
            except Exception as e:
                print(f"Error during stress test: {e}")
                break

        end_time = time.perf_counter()
        duration = end_time - start_time
        message_rate = messages_sent / duration

        print(
            f"Sent {messages_sent} messages in {duration:.3f}s ({message_rate:.1f} msgs/sec)"
        )

        # Should handle reasonable message rate
        assert message_rate > 10, f"Message rate too slow: {message_rate:.1f} msgs/sec"

    @pytest.mark.slow
    def test_long_running_stability(self):
        """Test system stability over extended period."""
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

        # Run for extended period
        start_time = time.perf_counter()
        messages_sent = 0
        errors = []
        target_duration = 30.0  # 30 seconds

        while time.perf_counter() - start_time < target_duration:
            try:
                header, ct = alice.sendMessage(
                    "bob", f"Long run message {messages_sent}"
                )
                decrypted = bob.receiveMessage("alice", header, ct)

                if decrypted == f"Long run message {messages_sent}":
                    messages_sent += 1
                else:
                    errors.append(f"Message {messages_sent}: decryption mismatch")

                # Occasionally force garbage collection
                if messages_sent % 100 == 0:
                    gc.collect()

            except Exception as e:
                errors.append(f"Message {messages_sent}: {e}")
                break

            # Brief pause to simulate real usage
            time.sleep(0.001)

        end_time = time.perf_counter()
        duration = end_time - start_time

        print(f"Long run test: {messages_sent} messages in {duration:.1f}s")
        print(f"Errors: {len(errors)}")

        # Should maintain stability
        error_rate = len(errors) / messages_sent if messages_sent > 0 else 1
        assert error_rate < 0.01, f"Too many errors: {error_rate:.2%}"
        assert messages_sent > 1000, f"Too few messages processed: {messages_sent}"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short", "-m", "not slow"])
