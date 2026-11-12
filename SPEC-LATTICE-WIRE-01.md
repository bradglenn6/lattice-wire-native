# SPEC-LATTICE-WIRE-01: Experimental PQ Datagram Envelope

**Status:** Experimental draft; not an Internet Standard  
**Version:** 1  
**Intended use:** Framing independently encrypted datagrams between peers whose ML-KEM public keys are provisioned out of band

## Abstract

This document defines a bounded binary envelope carrying one ML-KEM-512 ciphertext and one ChaCha20-Poly1305-protected payload per UDP datagram. It specifies byte offsets, flag meanings, key derivation, and receiver validation requirements.

This is an experimental framing proposal, not a complete transport or routing protocol. It does not define peer discovery, public-key authentication or distribution, reliable delivery, congestion control, anonymity, or a production-ready replay database. It makes no latency or SIMD performance guarantees.

## 1. Conventions and scope

The words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** express requirement levels for this draft.

All multibyte integer fields are unsigned and encoded in network byte order (big-endian). Implementations MUST parse and serialize individual fields explicitly; they MUST NOT use a packed C/C++ struct as the wire encoding. The KEM ciphertext is an opaque byte string in the encoding defined by FIPS 203.

Each frame carries a fresh ML-KEM-512 encapsulation to the recipient's provisioned public key. The public key and its authentication are out of band. Encapsulation produces a shared secret for deriving this frame's AEAD key.

This design can carry a one-way encrypted datagram without a preceding interactive handshake when the sender already has an authenticated recipient public key. It does **not** provide forward secrecy against later compromise of a recipient's static decapsulation key. Fresh encapsulation randomness alone does not provide that property. This draft is not suitable where that forward-secrecy guarantee is required.

## 2. Datagram size

The maximum frame size defined here is **1472 bytes**, corresponding to the UDP payload budget for a basic IPv4 packet with a 1500-byte MTU and no IP options. This is not a universal path-MTU guarantee.

The frame consists of:

| Component | Size |
|---|---:|
| Header | 32 bytes |
| ML-KEM-512 ciphertext | 768 bytes |
| AEAD nonce | 12 bytes |
| Encrypted application payload | 0–644 bytes |
| Poly1305 tag | 16 bytes |
| **Maximum total** | **1472 bytes** |

The total frame length is exactly `828 + payload_length` bytes. A receiver MUST reject a frame whose actual length does not equal that value. Senders MUST NOT rely on IP fragmentation. Implementations SHOULD select a lower configured maximum using path-MTU information; for a basic IPv6 path with a 1500-byte MTU, the corresponding UDP payload budget is 1452 bytes, before accounting for extension headers or tunnels.

## 3. Wire format

### 3.1 Header (32 bytes)

| Offset | Size | Field | Encoding and meaning |
|---:|---:|---|---|
| 0 | 2 | `magic` | `0x5A4C` (ASCII `"ZL"`), network byte order |
| 2 | 1 | `version` | `0x01` |
| 3 | 1 | `flags` | Bit assignments in Section 3.2 |
| 4 | 4 | `stream_id` | Sender-selected stream identifier |
| 8 | 8 | `sequence_number` | Sender sequence number for the stream |
| 16 | 8 | `destination_key_id` | Truncated identifier used only to select a provisioned recipient key |
| 24 | 2 | `payload_length` | Plaintext payload length; 0–644 |
| 26 | 2 | `header_length` | MUST be `32` |
| 28 | 4 | `reserved` | MUST be zero; receivers MUST reject nonzero values |

`destination_key_id` is not a public key, an authenticated identity, or a secure routing address. Provisioning MUST prevent ambiguous key-ID mappings; unknown or colliding IDs MUST be rejected.

### 3.2 Flags

| Bit mask | Name | Meaning |
|---:|---|---|
| `0x01` | `ACK_ONLY` | Payload is exactly one 8-byte `ack_sequence_number`, encoded big-endian, acknowledging the highest authenticated sequence received on this stream |
| `0x02` | `TELEMETRY` | Application-defined telemetry hint; it grants no privilege and MUST NOT change cryptographic processing |
| `0xFC` | Reserved | MUST be zero; receivers MUST reject frames with any reserved bit set |

When `ACK_ONLY` is set, `payload_length` MUST be 8. When it is clear, the payload is application data. Acknowledgments are informational; this envelope does not define retransmission or delivery guarantees.

### 3.3 Body

| Offset | Size | Field |
|---:|---:|---|
| 32 | 768 | ML-KEM-512 ciphertext |
| 800 | 12 | ChaCha20-Poly1305 nonce |
| 812 | `payload_length` | Encrypted payload |
| `812 + payload_length` | 16 | Poly1305 authentication tag |

The 768-byte ciphertext is the standard ML-KEM-512 ciphertext encoding. Implementations MUST NOT assume that it is safe to parse or reinterpret the ciphertext as application-defined fields. The 12-byte nonce is carried in cleartext and is authenticated as associated data.

## 4. Cryptographic processing

This section defines an experimental composition; it is not a substitute for independent cryptographic review.

### 4.1 Sending

For each frame, the sender MUST:

1. Encapsulate to the authenticated, provisioned ML-KEM-512 public key, obtaining ciphertext `ct` and shared secret `ss`.
2. Generate a fresh, unpredictable 12-byte nonce.
3. Encode the header, including the final payload length and flags.
4. Derive a 32-byte AEAD key as `SHAKE256(domain || ss || destination_key_id ||
   stream_id || nonce, 32)`, where `domain` is the 23-byte ASCII string
   `ZeroLabz-LatticeWire-v1`, `destination_key_id` is the 8-byte unsigned
   big-endian header value, and `stream_id` is the 4-byte unsigned big-endian
   header value. The KDF input is exactly 79 bytes.
5. Encrypt the payload using ChaCha20-Poly1305 with that key and nonce. The associated data is the exact concatenation `header || ct || nonce`.
6. Emit `header || ct || nonce || ciphertext || tag`.

The sender MUST use a conforming, reviewed ML-KEM and AEAD implementation. Secret material and intermediate keys SHOULD be erased when practical. The sequence number MUST NOT wrap within a stream; a sender starting a new sequence space MUST use a new stream ID.

### 4.2 Receiving

The receiver MUST perform bounded length and header validation before accessing body fields. It MUST reject unsupported versions, incorrect magic or header length, nonzero reserved bits or bytes, out-of-range payload lengths, and any frame whose actual length is not exactly `828 + payload_length`.

The receiver then selects the provisioned private key using `destination_key_id`, decapsulates the ciphertext, derives the AEAD key as in Section 4.1, and verifies/decrypts using the exact associated data `header || ct || nonce`. It MUST NOT expose plaintext or act on flags or payload contents unless authentication succeeds.

Replay checks MUST be applied to authenticated frames. A receiver MAY do a non-mutating preliminary check for efficiency, but unauthenticated input MUST NOT advance, create, or otherwise mutate replay state. Replay state is maintained per authenticated peer key and stream. Its persistence and window policy are deployment choices not specified here; deployments requiring replay prevention MUST define them explicitly.

## 5. MTU and transport behavior

This format defines a UDP payload, not a raw-IP protocol. Implementations MUST NOT bypass the host networking stack or assume that a 1500-byte link MTU is end-to-end available. They SHOULD use path-MTU discovery or a conservative configured datagram cap, and MUST reduce the maximum frame size when a path requires it. If the path cannot carry the 828-byte minimum frame without fragmentation, this format cannot carry a frame on that path.

The `destination_key_id`, `stream_id`, sequence number, flags, lengths, KEM ciphertext, and nonce are visible to observers. Encryption does not hide packet size, timing, or network endpoints. This format does not provide onion routing, geometric routing, traffic analysis resistance, congestion control, or denial-of-service protection.

## 6. Implementation and SIMD notes (non-normative)

ML-KEM arithmetic and encoding MUST follow FIPS 203. In particular, implementations MUST NOT substitute an incomplete or independently invented NTT, coefficient packing, Montgomery reduction, or decapsulation path for a conforming implementation.

AVX2, AVX-512, or other SIMD backends are implementation choices only. They MUST produce results equivalent to a conforming implementation, preserve constant-time behavior where required, and perform correct runtime CPU-feature dispatch. No register-allocation strategy, butterfly schedule, cycle count, or latency target is part of this wire specification. The often-quoted “eight registers hold a polynomial” observation does not establish a correct NTT implementation.

## 7. Security considerations and limitations

- A static recipient decapsulation key compromise can expose recorded frames addressed to that key. Deployments requiring forward secrecy need a separately designed and reviewed key-establishment or ratcheting protocol.
- The 64-bit destination key ID is a lookup hint, not an authenticator. Authentication comes from successful decapsulation and AEAD verification plus trusted key provisioning.
- Sequence numbers do not prevent replay without receiver-maintained state. The wire format alone is not statelessly replay-safe.
- Per-frame KEM encapsulation adds substantial bandwidth and computation. No sub-microsecond or zero-RTT performance claim is made.
- Public-key rotation, revocation, key-ID collision handling, rate limiting, congestion behavior, and error response policy require deployment-level design.
- This draft has not been standardized or formally analyzed. It MUST NOT be represented as FIPS-certified merely because it names FIPS 203 algorithms.

## 8. Interoperability checklist

An implementation claiming compatibility with this draft MUST:

- Encode the 32-byte header and all multibyte integers exactly as specified.
- Use standard ML-KEM-512 ciphertext encoding and ChaCha20-Poly1305.
- Derive the AEAD key and authenticate associated data exactly as specified.
- Enforce the exact frame-length equation and all reserved-bit rules.
- Authenticate before releasing plaintext or mutating replay state.
- Respect the configured path-MTU limit and avoid IP fragmentation.

## 9. Current reference implementation

`processPacket(frame)` performs **frame-structure validation only**. Its status is `FRAME_VALID_UNAUTHENTICATED`; it does not authenticate, decrypt, or mutate replay state. It reports validated offsets for the KEM ciphertext, nonce, encrypted payload, and tag. These offsets are bounded by the validated frame length. The addon does not retain the input buffer or create external buffers.

`processAuthenticatedPacket(frame, aead_key, replay_window)` performs structural validation, a non-mutating replay inspection, RFC 8439 ChaCha20-Poly1305 authentication/decryption, and then replay commit. The caller supplies an exact 32-byte AEAD key through a Node.js `Buffer`; it MUST already have been derived by a trusted key-establishment layer. `processZeroRttDatagram(frame, mlkem_secret_key, destination_key_id, replay_window)` instead validates the frame and destination, inspects replay state, ML-KEM-512 decapsulates, derives the key using the KDF above, authenticates/decrypts, then commits replay state. The API takes the expected local destination key ID and the 1632-byte secret key from its caller. Both operations require a caller-scoped replay window. Their `FRAME_AUTHENTICATED` status means only that the frame's AEAD tag verified and the sequence was committed; it does not independently establish the identity or authorization of the sender.

The addon also exports `generateMlKem512Keypair()` and `encapsulateMlKem512(public_key)` for sender-side use and test-fixture generation. These return copies in Node.js `Buffer`s; callers MUST protect and erase secret-key and shared-secret buffers when no longer needed. `resetReplayWindow(window)` explicitly clears replay history and MUST NOT be called during an active sequence space except when the application intentionally starts a new replay-state epoch. The benchmark resets its dedicated window per operation to make pre-generated frames repeatable; the reported accepted-path measurements include that reset call and should not be read as isolated crypto timings.

The AEAD associated data is the exact 812-byte prefix `header || KEM ciphertext || nonce`. Plaintext is decrypted into a bounded temporary buffer and copied into a new Node.js `Buffer` only after successful tag verification and replay commit. Authentication or replay failure throws an error and does not return plaintext. Callers handling network traffic SHOULD catch rejection and silently drop the datagram without sending an error response. The unified path wipes its candidate shared secret, derived AEAD key, and temporary plaintext. The caller remains responsible for securely erasing the secret-key `Buffer` when it is no longer needed.

`processZeroRttDatagramInPlace(frame, mlkem_secret_key, destination_key_id, replay_window)` is an opt-in mutable-buffer variant. It uses the protocol's variable-length layout: the 12-byte IETF ChaCha20-Poly1305 nonce is at offset 800, payload starts at offset 812, and the 16-byte tag follows the payload. It does not use a fixed payload offset of 828 or a 24-byte XChaCha nonce. Monocypher's IETF AEAD read path authenticates the ciphertext before writing plaintext and permits identical input/output buffers; a failed tag leaves the ciphertext unchanged. After decryption the replay commit is attempted; a losing concurrent duplicate is wiped in the original Buffer and rejected. On success, the returned object references the original `frame` Buffer and gives `plaintextOffset: 812` and `plaintextLength`; the payload bytes in that Buffer are now plaintext, while the tag and header remain present. The caller MUST only pass a Buffer it owns for mutation, and SHOULD discard or securely clear it after consuming the payload. This avoids an additional native-to-JavaScript plaintext copy but does not make the entire operation allocation-free: cryptographic state and the Node-API result object still require temporary storage.

## 10. Replay-window helper

`createReplayWindow()` creates an opaque replay window. `processAuthenticatedPacket` requires one and uses its non-mutating `Inspect` operation before AEAD verification. This early check may reject known duplicates or stale sequences but MUST NOT mutate state. After successful authentication, `CommitAfterAuthentication` atomically rechecks and records the sequence under a per-instance lock. Concurrent packets with the same sequence can both pass inspection, but at most one can commit and receive plaintext.

Each replay-window object MUST be scoped by the caller to one authenticated peer and stream. The caller MUST NOT share a window across unrelated peers or streams. The addon does not keep a global map keyed by unauthenticated header values. Unauthenticated frames passed to `processPacket`, and frames that fail AEAD verification, do not change replay state.

## 11. Cryptographic integration status

The native AEAD wrapper uses Monocypher 4.0.3 for ChaCha20-Poly1305; its source and license are recorded under `deps/monocypher`. The isolated ML-KEM-512 wrapper and PQClean clean sources are built and tested, with provenance and archived upstream status recorded under `deps/mlkem512/UPSTREAM.md`. The experimental `processZeroRttDatagram` path connects decapsulation, SHAKE256 key derivation, AEAD authentication/decryption, and post-authentication replay commit. The PQClean snapshot is retired and is not recommended as a maintained production dependency. This experimental composition has not received independent cryptographic review. It MUST NOT be treated as a production-ready transport or as sender authentication without authenticated provisioning of the destination public key and appropriate protocol-level peer authentication. The implementation MUST NOT use a handwritten Poly1305 routine or call a Poly1305 MAC over ad hoc slices as a substitute for RFC 8439 AEAD framing. The AEAD API MUST authenticate the full specified associated data and verify the tag before releasing plaintext.

The ML-KEM wrapper currently has randomized roundtrip, implicit-rejection, and end-to-end ingestion tests, but does not yet verify the NIST known-answer test data whose digest is listed in the vendored upstream metadata. Do not treat those tests as a conformance claim. Tests MUST include applicable NIST ML-KEM known-answer vectors and RFC 8439 ChaCha20-Poly1305 test vectors, including modified-tag rejection. Secret cleanup MUST use the crypto library's documented cleansing primitive or a platform-supported secure-zero API, on every success and failure path. Payload decryption MUST use only the validated encrypted-payload slice and MUST write only to a checked, bounded destination. Replay `Inspect` may be used as a non-mutating early filter; `CommitAfterAuthentication` may be called only after AEAD verification succeeds.
