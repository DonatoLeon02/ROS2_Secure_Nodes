# ROS2 Secure Nodes

## Project Overview

This project demonstrates secure cryptographic communication between two nodes in ROS2 Humble using modern elliptic curve cryptography and symmetric encryption. Most code is in C++ with a Python-based verifier script.

**Key Features:**
- Authenticated handshake
- Encrypted message exchange
- Digital signature verification
- ROS2 launch file for automated startup
- Service interface for dynamic communication

---

## How It Works

1. **Key Generation:**
   - Each node generates:
     - An X25519 ECDH keypair (for authenticated key exchange).
     - An Ed25519 signing keypair (for authenticating handshake and signing messages).

2. **Authenticated Handshake:**
   - Each node publishes:
     - X25519 public key (PEM)
     - Ed25519 public key (PEM)
     - Ed25519 signature over the ECDH public key
   - On receiving the handshake, the peer verifies the signature against the Ed25519 public key and, if successful, both compute a shared secret with X25519 ECDH. This secret (32 bytes) becomes the AES-256-GCM key.

   > **Note:** While the handshake signature *prevents basic key substitution* by binding the ECDH public key to an identity, it does **not prevent sophisticated man-in-the-middle (MITM) attacks** unless Ed25519 public keys are pre-shared, validated through PKI/certificates, or checked externally. Without such validation, an attacker can present their own keypairs and signatures to each side.

3. **Message Exchange:**
   - **Publisher Node:** Signs the plaintext payload using Ed25519, then encrypts the message with AES-256-GCM using a fresh random IV. The resulting message contains base64-encoded ciphertext + IV + tag + signature.
   - **Subscriber Node:** Decrypts with AES-256-GCM, verifies the signature over the recovered plaintext with the publisher's Ed25519 public key.

4. **Service Interface:**
   - The package defines a ROS2 service (see source/service definition) for dynamic payload exchanges or control operations. The service provides a way to trigger secure data transmission, key exchanges, or logging from external clients.

---

## Protocols Used

- **ECDH:** X25519 for secure shared secret creation.
- **Signatures:** Ed25519 for authenticating handshake and messages.
- **Encryption:** AES-256-GCM for confidentiality and integrity.
- **Encoding:** All binary fields base64-encoded for ROS transport.

---

## Usage

### Build

```bash
git clone https://github.com/DonatoLeon02/ROS2_Secure_Nodes.git
cd ROS2_Secure_Nodes
colcon build --symlink-install
source install/setup.bash
```

### Launch Nodes

Use the provided launch file:
```bash
ros2 launch secure_nodes secure_node.launch.py
```
This launches both publisher and subscriber nodes with default parameters.

### Service Usage

A ROS2 service is defined for secure communication tasks. See the relevant `.srv` file and node source for exact interface and usage. You can call the service from another ROS2 node, CLI, or the verifier script for dynamic control or to trigger secure data transfer.

### Verifier Script

A Python script is provided to audit message logs and verify message integrity and authenticity offline.

Example usage:
```bash
python3 scripts/verifier.py --log logs/comm_log.txt --pubkey certs/publisher_ed25519.pem
```
Show all options:
```bash
python3 scripts/verifier.py --help
```

---

## Security Analysis & Vulnerabilities

While this implementation uses strong cryptographic primitives, a few important vulnerabilities and mitigations are highlighted below:

- **Man-In-The-Middle Attack Risk:** The handshake authenticates the ECDH public key with Ed25519, but unless Ed25519 public keys are pre-shared or verified outside-band/by PKI, an attacker controlling the network could substitute their own keypairs to both parties. **Ideal mitigation**: pre-share public keys, use a PKI, or use an authenticated key-exchange protocol such as TLS or Noise.
- **Replay Attacks:** Both handshake and messages are susceptible to replay without nonces, timestamps, or sequence numbers. **Mitigation**: add metadata and enforce freshness/ordering.
- **Weak Key Derivation:** The AES key is directly the shared secret. **Mitigation**: use a KDF such as HKDF-SHA256.
- **IV Reuse Risks, Forward Secrecy, Logging Sensitivities, and DoS attacks:** See original README's recommendations for operational precautions.

### Key Recommendations (from implementation notes)

1. Use HKDF-SHA256 for AES key derivation.
2. Authenticate Ed25519 public keys (pre-share via config, PKI, etc.).
3. Rotate ECDH keys periodically.
4. Add replay/ordering metadata to messages.
5. Secure key storage and stop logging private/symmetric keys.
6. Harden crypto operation rate limiting.

---

## Future Work

- Integrate HKDF for key derivation.
- Add PKI authentication for identities.
- Make ECDH keys ephemeral or enable session rekeying.
- Add replay/ordering metadata to messages and handshakes.
- Strengthen service and message interfaces for security.
- Harden code for side-channel attacks and robust error handling.

---

## Repository Structure

- `src/` — C++ nodes for secure messaging
- `scripts/` — Python verifier and utilities
- `launch/secure_node.launch.py` — ROS2 launch file to start nodes
- `srv/` — Service definition and usage
- `certs/` — Key and cert helpers
- `docs/` — Documentation and security notes

---

## License

MIT License (see LICENSE)
