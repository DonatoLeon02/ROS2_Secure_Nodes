# Secure communication — protocol and security overview

This document describes how secure communication is established between the publisher and subscriber nodes: which cryptographic primitives are used, how the shared secret (symmetric key) is generated, and where digital signatures are applied to provide authentication and integrity.

## High-level overview
- Each node holds two keypairs:
  - An X25519 ECDH keypair used only for key agreement (generating a shared secret).
  - An Ed25519 signing keypair used to authenticate public keys and to sign message payloads.
- Nodes perform an authenticated ECDH handshake: each node publishes its ECDH public key plus its Ed25519 public key and an Ed25519 signature that authenticates the ECDH public key.
- After successful handshake verification, both nodes derive the same shared secret via X25519 ECDH; that secret is turned into an AES‑256 key.
- The publisher signs the plaintext with Ed25519 and then encrypts the plaintext with AES‑256‑GCM. The subscriber decrypts with AES‑GCM and verifies the Ed25519 signature on the recovered plaintext.

## Components
- Publisher node: generates keys, performs authenticated handshake, signs plaintext, encrypts with AES‑GCM, publishes `custom_msgs::msg::SignedData`.
- Subscriber node: verifies handshake signatures, performs ECDH to derive AES key, decrypts received `SignedData` and verifies message signatures.
- Handshake messages: carry ECDH public key PEM, Ed25519 public key PEM, and an Ed25519 signature that binds the ECDH public key to the signer.

## Cryptographic primitives
- ECDH: X25519 (OpenSSL `EVP_PKEY_X25519`) — key agreement producing a 32‑byte shared secret.
- Signatures: Ed25519 (OpenSSL `EVP_PKEY_ED25519`) — used both to authenticate handshake keys and to sign message payloads.
- Symmetric encryption: AES‑256‑GCM — provides confidentiality and integrity (authentication tag).
- Message encoding: binary fields (ciphertext, IV, tag, signatures) are base64-encoded for transport in ROS messages.

## Authenticated handshake (detailed)
1. Key generation (per node):
   - Generate X25519 ECDH keypair.
   - Generate Ed25519 signing keypair.
2. Handshake message contents:
   - `ecdh_pubkey`: X25519 public key in PEM.
   - `ed25519_pubkey`: Ed25519 public key in PEM.
   - `signature`: base64(Ed25519 signature over the DER bytes of the ECDH public key).
     - Implementation detail: the ECDH public key is converted to its DER (i2d) representation and those raw bytes are signed with Ed25519 (one‑shot sign).
3. Receiver processing:
   - Load peer's Ed25519 public key (PEM).
   - Verify the handshake `signature` against the peer's ECDH DER bytes using Ed25519.
   - If verification fails, reject the handshake and do not derive keys.
   - If verification succeeds, perform X25519 ECDH with the peer's ECDH public key to compute the shared secret.

## Shared secret → AES key
- X25519 ECDH produces a 32‑byte shared secret.
- This implementation uses the shared secret (first 32 bytes) directly as the AES‑256 key.
- Notes: In production, a KDF (HKDF) with context info and key separation is recommended instead of raw shared‑secret truncation.

## Message signing and encryption flow (publisher)
1. Prepare plaintext payload (in this project: a fixed Lorem ipsum string).
2. Sign plaintext: compute Ed25519 signature over the plaintext bytes. Store base64(signature) in the message.
3. Encrypt plaintext: AES‑256‑GCM with a fresh 96‑bit IV per message produces ciphertext + 16‑byte tag.
   - Store base64(ciphertext) in `SignedData.data`.
   - Store base64(iv) in `SignedData.iv`.
   - Store base64(tag) in `SignedData.tag`.
4. Publish the SignedData message.

Rationale: signing plaintext before encryption gives message authenticity independent of confidentiality; the signature can be verified after decryption to ensure the payload originated from the claimed signer and was not tampered with.

## Reception: decryption and verification (subscriber)
1. Base64-decode ciphertext, IV, tag, and signature.
2. Decrypt with AES‑256‑GCM using the derived AES key and provided IV/tag.
   - If decryption fails (authentication tag mismatch), reject the message.
3. Verify the Ed25519 signature over the recovered plaintext using the publisher's Ed25519 public key (from the handshake).
   - If signature verification succeeds, accept the message as authentic and intact.

## Where digital signatures fit in
- Handshake signatures (Ed25519) bind a node's ECDH public key to its identity (Ed25519 public key). This prevents man‑in‑the‑middle substitution of ECDH keys.
- Message signatures (Ed25519) authenticate the message payload and provide non‑repudiation. They are applied to the plaintext prior to encryption so that the recipient can validate the content after successful decryption.

## Security considerations / recommendations
- Current implementation uses the raw X25519 shared secret as the AES key. For stronger key hygiene use a KDF (e.g., HKDF‑SHA256) with explicit salt/info to derive separate keys for encryption and MAC.
- Never expose AES keys in submission artifacts; signature verification provides authenticity evidence without revealing symmetric keys.
- Ensure IV uniqueness for AES‑GCM—this implementation uses a random 96‑bit IV per message; monitoring uniqueness is recommended.
- Keep private keys protected (persist them securely if required across runs).

## Current vulnerabilities and standard mitigations
- Key substitution / MITM during handshake
  - Vulnerability: an active attacker that can intercept and modify handshake messages can replace ECDH public keys and, if the receiver trusts the provided signing key, complete a MITM.
  - Fixes: pre‑share and verify Ed25519 public keys or use a PKI/certificates; alternatively use an authenticated key‑exchange protocol (TLS or Noise). Include key identifiers and sign additional context (nonces/timestamps).

- Replay of handshake or messages
  - Vulnerability: previously observed handshake or message packets can be replayed to re‑establish sessions or re‑deliver valid messages.
  - Fixes: include nonces, timestamps, or session IDs in the signed handshake and in message metadata; enforce freshness checks and sequence numbers.

- Weak key derivation
  - Vulnerability: using the raw X25519 output directly as an AES key provides no KDF‑based separation.
  - Fixes: run the ECDH shared secret through HKDF‑SHA256 (with salt/info) to derive distinct keys (encryption, IV derivation, etc.).

- Lack of forward secrecy if long‑lived ECDH keys are used
  - Vulnerability: compromise of long‑term ECDH private keys exposes past traffic.
  - Fixes: use ephemeral ECDH keys per session or periodic rekeying; rotate keys and use session lifetimes.

- IV reuse for AES‑GCM
  - Vulnerability: reusing IVs with the same AES key can break confidentiality/integrity.
  - Fixes: guarantee unique IVs (counter, deterministic per‑message nonce derivation, or sufficiently large random IVs with collision checks).

- Message replay/ordering attacks
  - Vulnerability: signed messages can be replayed and still verify.
  - Fixes: include sequence numbers or signed timestamps and reject duplicates or out‑of‑order messages.

- Logging sensitive material
  - Vulnerability: logging raw secrets (AES key, shared secret) exposes keys via logs.
  - Fixes: never log private keys or raw symmetric keys; only log non‑sensitive diagnostics or key fingerprints.

- Denial of Service through expensive crypto operations
  - Vulnerability: unauthenticated mass handshake attempts can exhaust CPU via signature verification.
  - Fixes: rate‑limit handshakes, perform lightweight prechecks before expensive ops, and cap concurrent handshake processing.

- Implementation correctness and side channels
  - Vulnerability: incorrect error handling, non‑constant time comparisons, or weak RNG can leak secrets or introduce bugs.
  - Fixes: validate all return values, use constant‑time comparisons for sensitive checks, rely on OS CSPRNG and avoid exposing timing differences.

Short prioritized recommendations
1. Use HKDF‑SHA256 on the X25519 shared secret to derive keys.
2. Pre‑share or otherwise authenticate Ed25519 public keys (or use a PKI) to prevent MITM.
3. Use ephemeral ECDH keys or session rekeying for forward secrecy.
4. Add nonces/timestamps and sequence numbers to signed handshake and messages to prevent replay.
5. Stop logging raw secrets and ensure secure key storage.

End of document.
