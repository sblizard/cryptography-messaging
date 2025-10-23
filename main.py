from cryptography.hazmat.primitives.asymmetric.ec import (
    generate_private_key,
    EllipticCurvePrivateKey,
    SECP256R1,
    EllipticCurvePublicKey,
)

from messenger import MessengerServer, MessengerClient, Certificate


def error(s):
    print("=== ERROR: " + s)


print("Initializing Server")
server_sign_sk: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
server_enc_sk: EllipticCurvePrivateKey = generate_private_key(SECP256R1())
server: MessengerServer = MessengerServer(server_sign_sk, server_enc_sk)

server_sign_pk: EllipticCurvePublicKey = server_sign_sk.public_key()
server_enc_pk: EllipticCurvePublicKey = server_enc_sk.public_key()

print("Initializing Users")
alice: MessengerClient = MessengerClient(
    name="alice", server_signing_pk=server_sign_pk, server_encryption_pk=server_enc_pk
)
bob: MessengerClient = MessengerClient(
    name="bob", server_signing_pk=server_sign_pk, server_encryption_pk=server_enc_pk
)
carol: MessengerClient = MessengerClient(
    name="carol", server_signing_pk=server_sign_pk, server_encryption_pk=server_enc_pk
)

print("Generating Certs")
certA: Certificate = alice.generateCertificate()
certB: Certificate = bob.generateCertificate()
certC: Certificate = carol.generateCertificate()

print("Signing Certs")
sigA: bytes = server.signCert(cert=certA)
sigB: bytes = server.signCert(cert=certB)
sigC: bytes = server.signCert(cert=certC)

print("Distributing Certs")
try:
    alice.receiveCertificate(certificate=certB, signature=sigB)
    alice.receiveCertificate(certificate=certC, signature=sigC)
    bob.receiveCertificate(certificate=certA, signature=sigA)
    bob.receiveCertificate(certificate=certC, signature=sigC)
    carol.receiveCertificate(certificate=certA, signature=sigA)
    carol.receiveCertificate(certificate=certB, signature=sigB)
except:
    error("certificate verification issue")

print("Testing incorrect cert issuance")
mallory: MessengerClient = MessengerClient(
    name="mallory", server_signing_pk=server_sign_pk, server_encryption_pk=server_enc_pk
)
certM: Certificate = mallory.generateCertificate()
try:
    alice.receiveCertificate(certificate=certM, signature=sigC)
except:
    print("successfully detected bad signature!")
else:
    error("accepted certificate with incorrect signature")

print("Testing Reporting")
content: str = "inappropriate message contents"
reportPT, reportCT = alice.report(name="Bob", message=content)
decryptedReport: str = server.decryptReport(ct=reportCT)
if decryptedReport != reportPT:
    error("report did not decrypt properly")
    print(reportPT)
    print(decryptedReport)
else:
    print("Reporting test successful!")

print("Testing a conversation")
print("Alice certs:", alice.certs.keys())
print("Bob certs:", bob.certs.keys())
header, ct = alice.sendMessage(name="bob", message="Hi Bob!")
msg: str | None = bob.receiveMessage(name="alice", header=header, ciphertext=ct)
if msg != "Hi Bob!":
    error("message 1 was not decrypted correctly")

header, ct = alice.sendMessage(name="bob", message="Hi again Bob!")
msg = bob.receiveMessage(name="alice", header=header, ciphertext=ct)
if msg != "Hi again Bob!":
    print("got:", msg)
    error("message 2  was not decrypted correctly")

header, ct = bob.sendMessage(name="alice", message="Hey Alice!")
msg = alice.receiveMessage(name="bob", header=header, ciphertext=ct)
if msg != "Hey Alice!":
    print("got:", msg)
    error("message 3 was not decrypted correctly")

header, ct = bob.sendMessage(name="alice", message="Can't talk now")
msg = alice.receiveMessage(name="bob", header=header, ciphertext=ct)
if msg != "Can't talk now":
    print("got:", msg)
    error("message 4 was not decrypted correctly")

header, ct = bob.sendMessage(name="alice", message="Started the homework too late :(")
msg = alice.receiveMessage(name="bob", header=header, ciphertext=ct)
if msg != "Started the homework too late :(":
    print("got:", msg)
    error("message 5 was not decrypted correctly")

header, ct = alice.sendMessage(name="bob", message="Ok, bye Bob!")
msg = bob.receiveMessage(name="alice", header=header, ciphertext=ct)
if msg != "Ok, bye Bob!":
    print("got:", msg)
    error("message 6  was not decrypted correctly")

header, ct = bob.sendMessage(
    name="alice", message="I'll remember to start early next time!"
)
msg = alice.receiveMessage(name="bob", header=header, ciphertext=ct)
if msg != "I'll remember to start early next time!":
    print("got:", msg)
    error("message 7 was not decrypted correctly")

print("conversation completed!")


print("Testing handling an incorrect message")

h, c = alice.sendMessage(name="bob", message="malformed message test")
m = bob.receiveMessage(name="alice", header=h, ciphertext=ct)
if m is not None:
    print("message:", m)
    error("didn't reject incorrect message")
else:
    print("success!")


print("Testing complete")
