# Cryptography Messenger

A secure end-to-end encrypted messaging client implementing the Double Ratchet algorithm, as used in Signal and WhatsApp. This project was developed as part of COMP 537: Cryptography Fall 2025 Programming Assignment 2.

## Features

- **End-to-End Encryption**: Secure messaging using the Double Ratchet algorithm
- **Forward Secrecy**: Past messages remain secure even if current keys are compromised
- **Break-in Recovery**: Communication security is restored after sending a single uninterrupted message
- **Certificate-Based Authentication**: Public key distribution through server-signed certificates
- **Message Reporting**: Ability to report abusive messages with CCA-secure El-Gamal encryption
- **Memory Efficient**: O(1) key storage independent of message count

## Architecture

The implementation consists of two main components:

### MessengerClient
Handles user-side operations including:
- Certificate generation and verification
- Message encryption/decryption using Double Ratchet
- Secure key ratcheting for forward secrecy
- Message reporting functionality

### MessengerServer
Manages server-side operations including:
- Certificate signing with ECDSA
- Decryption of abuse reports
- Public key distribution and verification

## Cryptographic Primitives

- **Key Exchange**: Elliptic Curve Diffie-Hellman (ECDH) on curve P-256
- **Symmetric Encryption**: AES-GCM for authenticated encryption
- **Key Derivation**: HKDF with SHA256 for DH key ratcheting
- **MAC**: HMAC with SHA256 for symmetric key ratcheting
- **Digital Signatures**: ECDSA with SHA256 for certificate signing
- **Public Key Encryption**: CCA-secure El-Gamal for message reporting

## Requirements

- Python 3.12+
- `cryptography` library (^46.0.2)


## API Reference

### MessengerClient

#### `generateCertificate() -> Certificate`
Generates a certificate containing the client's public key for key exchange.

#### `receiveCertificate(certificate: Certificate, signature: bytes)`
Stores a certificate from another client after verifying the server's signature.

#### `sendMessage(name: str, message: str) -> Tuple[MessageHeader, bytes]`
Encrypts and sends a message to the specified user using the Double Ratchet algorithm.

#### `receiveMessage(name: str, header: MessageHeader, ciphertext: bytes) -> str | None`
Decrypts a message from the specified user. Returns `None` if tampering is detected.

#### `report(name: str, message: str) -> Tuple[str, bytes]`
Creates an encrypted abuse report. Returns both plaintext and ciphertext for testing.

### MessengerServer

#### `signCert(certificate: Certificate) -> bytes`
Signs a certificate with the server's private key using ECDSA.

#### `decryptReport(ct: bytes) -> str`
Decrypts an abuse report using the server's private decryption key.

## Security Properties

### Forward Secrecy
- Old message keys are deleted after each ratchet step
- Compromised current keys cannot decrypt past messages
- Achieved through continuous DH and symmetric key ratcheting

### Break-in Recovery
- New DH key exchanges restore security after compromise
- Single uninterrupted message is sufficient to regain security
- Implemented through the DH ratchet mechanism

### Authentication
- Server-signed certificates prevent key tampering
- ECDSA signatures ensure certificate authenticity
- Message headers are authenticated to prevent manipulation