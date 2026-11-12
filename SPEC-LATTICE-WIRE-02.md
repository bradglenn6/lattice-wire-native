# SPEC-LATTICE-WIRE-02: Ephemeral Resumption & Transport Architecture

**Status:** Draft; architectural decisions recorded, wire specification incomplete  
**Version:** 2  
**Relationship to v1:** Independent protocol version; no v1 parser or frame semantics are changed

## Abstract

This document records settled architectural decisions and a provisional
framing direction for resuming a session established through an ML-KEM-based
exchange. It separates session resumption from SPEC-LATTICE-WIRE-01 rather
than overloading the v1 header or reinterpreting its ciphertext field.

This is not yet a complete, interoperable protocol. The unresolved
requirements in Section 8 MUST be specified and reviewed before
implementations claim interoperability or production security. The
provisional resumed-frame encoding is in Section 6 and candidate handshake
frames are in Section 8.1; handshake delivery, nonce uniqueness,
replay-state lifecycle, and other requirements remain unresolved before
implementing a conforming parser.

## 1. Goals and non-goals

The design goals are:

- Keep v1 framing, parsing, and cryptographic behavior unchanged.
- Give v2 an unambiguous wire version and packet-type discrimination.
- Avoid a full ML-KEM decapsulation on every resumed datagram.
- Allow datagram loss and reordering without advancing a shared linear key
  chain once per packet.
- Keep transmit and receive key schedules independent.
- Authenticate before releasing plaintext or committing replay state.
- Prefer self-contained encrypted tickets over pointers into mutable,
  process-local session tables.

Resumption uses proof of possession of a client-held secret, but does not by
itself authenticate a real-world identity, prevent theft of that secret,
provide reliable delivery, conceal traffic metadata, or make replay
protection stateless. No latency or throughput target is guaranteed by this
architecture.

## 2. Settled architectural decisions

### 2.1 Client proof of possession

The client proves possession of a 32-byte `K_client_resume`, provisioned
inside the protected initial-handshake response and sealed inside the
responder's opaque ticket. The ticket alone MUST NOT be sufficient to derive
the resumed traffic keys.

The proposed canonical derivation removes the separate `TicketID` and binds
the resume secret to the 16-byte `connection_id`, ticket-issuance STEK epoch,
and 12-byte ticket salt:

`K_client_resume = SHAKE256(label || connection_id || uint32_be(issue_epoch) || ticket_salt || ss, 32)`

Here `label` is the 41-byte ASCII string
`SPEC-LATTICE-WIRE-02/KDF/HANDSHAKE-RESUME` without a NUL terminator, and
`ss` is the 32-byte ML-KEM shared secret. The fixed-size inputs make this
concatenation unambiguous. This is the current proposal, not a settled
interoperable KDF: the client and server must receive the same `ticket_salt`
and `issue_epoch`, and the protected handshake response and ticket format
must carry or unambiguously derive them. The updated provisional framing in
Section 6 carries both. The protocol must distinguish this STEK issue epoch
from the resumed-transport epoch in the frame header.
From `K_client_resume`, the schedule is proposed to derive distinct
client-to-server and server-to-client traffic keys and direction IVs using
`connection_id || uint32_be(transport_epoch)`; the need for `K_pop` and any
separate MAC remains unresolved.

For resumed packets, authentication MUST bind the canonical `connection_id`,
protocol version, packet type, epoch, sequence number, explicit nonce, and
other required cleartext context through the AEAD AAD and/or a separately
specified MAC keyed by `K_pop`. The final design MUST choose and specify the
construction. Successful verification under keys derived from
`K_client_resume` proves possession of that secret for the packet; it does
not prove a civil identity or prevent replay of a previously valid packet.
Replay defense is separately required by Section 2.2.

Dual KEM encapsulation on every resumed packet is out of scope: it would
reintroduce a KEM operation in the resumption path and defeat the goal of
avoiding repeated decapsulation.

### 2.2 Epoch and replay defense

Tickets are accepted only within a bounded epoch policy. The transport epoch
must be within the configured current/previous traffic-key overlap; the
ticket's STEK issue epoch is separately checked against ticket validity and
the retained key window. A cleartext epoch or timestamp MAY be used for a
cheap plausibility rejection before ticket decryption, but MUST NOT be
sufficient to accept a ticket: authenticated ticket contents remain
authoritative. Exact epoch duration, clock-skew allowance, and transition
behavior remain unresolved.

Within an authenticated session, sequence numbers are scoped by direction
and epoch and checked against a sliding replay window. The window MUST allow
the specified out-of-order range while rejecting duplicates and packets
older than its floor. A preliminary inspect is read-only. The sequence
bitmap/floor is committed only after AEAD authentication. Failed
authentication MUST NOT advance replay state. A packet that loses a race at
commit MUST NOT expose plaintext; any in-place plaintext MUST be securely
erased before rejection.

The intended native implementation may use an atomic bitmap or another
bounded synchronization mechanism. Lock-free operation is an optimization,
not a wire-level requirement; any implementation MUST be race-free and
define safe state ownership, publication, and reclamation. A process-local
window does not prevent duplicate acceptance across independent workers or
after restart. Deployment-wide replay guarantees therefore require shared
coordination or an explicitly weaker guarantee. A replay-state lookup based
on the unauthenticated `connection_id` MUST NOT create state or be treated as
an acceptance decision. A read-only tentative inspection MAY occur after
ticket authentication and verification of its connection binding, but before
outer-payload authentication; replay-state mutation and acceptance MUST still
wait until outer-payload authentication succeeds.

The supplied phrase “single-use bounded temporal epochs” is not a single-use
ticket rule: multiple datagrams may use a valid resumption ticket within its
accepted epoch, subject to the per-session sequence replay window.

## 3. Version and packet discrimination

Every v2 frame begins with a fixed 32-byte header. All multi-byte integers
MUST use network byte order. Implementations MUST parse fields explicitly and
MUST NOT use a packed C/C++ struct as the wire representation.

| Offset | Size | Proposed field | Status |
|---:|---:|---|---|
| 0 | 2 | Protocol version, exactly `0x0002` | Required |
| 2 | 2 | Frame type: `0x0001` Handshake Initiation, `0x0002` Client Resumed Transport, `0x0003` Handshake Response, `0x0004` Server Resumed Transport; `0x0005` is an unassigned client-application-frame candidate | Candidate |
| 4 | 4 | Frame-specific epoch | `client_epoch_hint` in `0x0001`; `transport_epoch` in resumed frames (`0x0002`, `0x0004`, candidate `0x0005`) and server response |
| 8 | 8 | Frame-specific sequence | Handshake-init candidate requires zero; otherwise big-endian and scoped by direction and epoch |
| 16 | 16 | Frame-specific identifier | `client_handshake_id` in `0x0001`/`0x0003`; assigned `connection_id` in `0x0002`/`0x0004`/candidate `0x0005` |

The current frame candidates use type-specific layouts: `0x0001` carries a
client handshake identifier and ML-KEM ciphertext; `0x0003` echoes that
identifier and carries an encrypted issuance response; `0x0002` is the
ticket-bearing client-to-server resumed frame in Section 6; and `0x0004` is
a compact server-to-client resumed frame without a ticket. The issue epoch
inside a ticket selects the STEK; it is distinct from `transport_epoch`,
which scopes directional keys and replay state.

A later candidate assigns `0x0005` to an established client-to-server
application datagram, using a 32-byte header, encrypted payload, and 16-byte
tag analogous to `0x0004`. This is a new wire-format candidate, not an
implicit change to `0x0002`: the ticket-bearing initial resumption request
and subsequent established application frames have different purposes and
must have separately specified layouts, authentication context, and replay
state. Update the frame registry and all implementations together before
using `0x0005`; existing parsers must continue to reject unknown types.

Separate frame types allow cheap direction-specific dispatch and prevent a
valid `0x0004` frame from being accepted as a `0x0005` frame by a strict
parser. The type value is public, however, and is not authentication by
itself. It must be included in the AEAD-authenticated header, and the
client-to-server and server-to-client keys/nonces must remain independently
derived with their direction flags. A modified type must fail authentication
if it reaches AEAD; a wrong-type early drop is safe only as a stateless
format rejection and must not mutate replay or connection state.

The accompanying `client_wire_v2.hpp` is illustrative, not a complete
implementation of this candidate. Its `fetch_add` followed by a store at
the sequence ceiling has the same concurrent exhaustion race described for
server egress; reserve sequence numbers with a non-wrapping checked
compare/exchange operation. Its overlap arithmetic uses unchecked
pointer-plus-length operations and checks the full output capacity instead
of only bytes written; use overflow-safe range checks over the active output
region or explicitly forbid overlap. The Node-API constructor must validate
connection-ID, key, and IV lengths and check the finite-integral epoch
conversion result before using `epoch`; the sample ignores the helper's
boolean result, so invalid input can leave the variable uninitialized.
Handle state-allocation failure and an uninitialized wrapper before dereferencing
`state_`.

The shown client constructor also accepts a raw transmit key and base IV from
JavaScript. In production, derive and retain these in native-owned state
from the authenticated resumption secret and the client-to-server direction
context; the matching server receive material must derive identically from
the same authenticated context without sharing the server-to-client key.
If raw key injection is retained for tests, confine it to a test-only API.
Finally, the client and other proposed wrapper initializers must share one
environment instance-data owner; each `SetInstanceData` call replaces the
environment's single slot rather than registering an independent per-class
finalizer.

A v1 parser MUST reject version `0x0002` before interpreting any v2-specific
fields. A v2 parser MUST reject unsupported versions and unknown frame types.

Frame type MUST select one fixed layout. Each type needs a specified
fixed-field layout, length equation, and associated-data definition.
Receivers MUST derive payload bounds from a validated frame length and an
explicit length field or an unambiguous type-specific length equation.

The proposed 32-byte header has no payload-length field. The final wire format
MUST therefore allocate a defined length field or specify unambiguous
type-specific length equations and maximum ticket/payload sizes.

## 4. Session establishment and ticket model

The initial exchange may use ML-KEM to establish shared keying material.
Ticket issuance is a responder-to-client protocol action and therefore
requires an explicit authenticated response frame; a one-way KEM datagram
alone does not complete ticket delivery.

The intended resumption model is:

1. The responder validates and authenticates the initial exchange according
   to a separately specified peer-authentication policy.
2. The responder creates a fresh session secret, issue epoch, expiry, and any
   required peer-binding data.
3. The responder encrypts and authenticates that state in an opaque ticket
   using a rotating server ticket-encryption key (STEK).
4. The responder delivers the opaque ticket and the inputs needed for the
   client to derive its resumption secret inside the protected handshake
   response. The client MUST protect the ticket and derived secret and MUST
   NOT treat the ticket alone as sufficient key material.
5. A resumed datagram carries the opaque ticket and proves possession of
   `K_client_resume` through the specified packet-authentication construction.
   The server validates the ticket, checks expiry and epoch policy, derives
   packet keys, verifies the record, then applies replay policy.

Tickets are bearer credentials unless bound to a client-held secret or
authenticated identity. A ticket identifier is not itself secret. Ticket
contents MUST be authenticated and confidential. The proposed inner ticket
plaintext is exactly 80 bytes:

| Offset | Size | Field | Encoding |
|---:|---:|---|---|
| 0 | 32 | `client_resume_key` | Opaque 32-byte secret |
| 32 | 16 | `connection_id` | Opaque 16-byte identifier |
| 48 | 8 | `issued_at` | Unsigned POSIX seconds, big-endian |
| 56 | 8 | `expires_at` | Unsigned POSIX seconds, big-endian |
| 64 | 8 | `initial_seq_floor` | Unsigned sequence baseline, big-endian |
| 72 | 4 | `flags` | Unsigned bitfield, big-endian; assignments TBD |
| 76 | 4 | `reserved` | MUST be zero |

After successful ticket AEAD verification, the receiver MUST reject nonzero
reserved bytes, unsupported flag bits, `issued_at > now`, `now >= expires_at`,
or `expires_at <= issued_at`. It MUST compare the inner `connection_id`
against the outer header's 16-byte identifier in constant time before
processing the application payload. Ticket bytes MUST be parsed explicitly;
a packed native struct MUST NOT be treated as the wire representation. The sample
serialization's use of `std::byteswap` is C++23, not C++20; implementations
targeting C++20 must use explicit byte-order helpers or another compatible
method.

`initial_seq_floor` is the proposed baseline for initializing the
session/direction replay window. Whether the first accepted packet must be
strictly greater than this value or may equal it, and how the ticket's
baseline relates to each traffic direction, remain to be specified.

The updated provisional ticket envelope is 112 bytes: a 4-byte issue epoch,
a 12-byte CSPRNG ticket salt, 80 bytes of encrypted ticket plaintext, and a
16-byte AEAD tag. The salt derives a per-ticket AEAD key; the AEAD uses a
fixed all-zero 12-byte IETF nonce. Repeated salts under the same STEK,
connection ID, and issue epoch repeat the per-ticket key and nonce, so salt
collision probability and per-context issuance limits must be addressed.
The ticket AEAD AAD and key selection remain subject to final specification.
A 16-byte tag alone does not provide confidentiality. STEK rotation, overlap
windows, revocation, expiry units, and maximum lifetime MUST be specified.
Ticket decryption success MUST NOT be treated as proof of client identity or
possession of `K_client_resume`.

An opaque ticket avoids a mutable session-table lookup, but does not eliminate
all server state: replay prevention across workers and restarts requires a
shared, persistent, or otherwise coordinated replay mechanism, or an explicit
weaker replay policy. Per-process replay windows alone do not prevent the same
ticket/packet from being accepted by multiple workers. A separate
boot-scoped-ticket candidate in Section 8.1 invalidates pre-restart tickets
when volatile replay state is lost, at the cost of requiring a fresh handshake.

The attached STEK-validation sketch is not a valid client-side resumption
gate. The STEK/master key is server secret material: the client receives and
retains the opaque ticket and its separately derived `K_client_resume`, but
must not receive the server key or decrypt the ticket. Ticket opening and
validation belong on the server before it derives resumed packet keys; the
client proves possession of its resume secret with packet authentication.
Passing `stekMasterKey` into a client-facing `LatticeConnection` constructor
would expose the server's ticket-forging/decryption capability, and setting
`Established` based on a client-side ticket check would not authenticate the
server or the resumption context.

The proposed 112-byte `[96-byte ciphertext || 16-byte tag]` ticket also
conflicts with the provisional 112-byte envelope defined here, which is
`uint32_be(ticket_issue_epoch) || ticket_salt[12] || ciphertext[80] || tag[16]`.
Its suggested 96-byte plaintext (`connection_id[16] || epoch[4] ||
resume_key[32] || padding[44]`) is a different ticket schema from the
provisional 80-byte plaintext with issue/expiry times, sequence baseline,
flags, and reserved bytes. These representations and their ownership must
not be mixed or parsed interchangeably. Select one canonical schema, specify
its exact envelope, KDF, nonce, AAD, lifetime, and field checks, and update
all frame-size arithmetic and KATs together.

The sketch's all-zero XChaCha nonce under a long-term STEK/master key is
unsafe if that key encrypts more than one ticket: repeating a key/nonce pair
with ChaCha20-Poly1305 breaks confidentiality and can undermine authenticity.
The current candidate avoids direct reuse by deriving a per-ticket subkey
from the STEK and a fresh salt, then using a fixed nonce under that derived
key; its salt-collision risk and issuance limits remain as documented in
Sections 4.1 and 8.1. Any alternative must establish a unique key/nonce pair
per ticket with an explicit, reviewed construction; a comment saying
"ticket-specific nonce derivation" is not a specification.

The candidate ticket also needs authenticated canonical field validation.
It must define suite and protocol-version binding in the ticket context,
validate all reserved/padding bytes (rather than merely describing them as
zeros), and apply a clear issue/expiry policy. Connection-ID binding is
useful routing/context binding but is not a substitute for authenticating
the ticket or proving possession of `K_client_resume`. If an implementation
does decrypt a ticket into a caller-provided resume-key output, it must clear
that output before any early return and wipe it on every failure; however,
that operation belongs in the trusted server ticket-opening path, not the
client Node-API constructor.

#### Alternative fixed-size ticket with random XChaCha nonce

A later candidate keeps a 112-byte opaque ticket as
`ticket_nonce[24] || ciphertext[72] || tag[16]`. The encrypted 72-byte
plaintext is proposed as `connection_id[16] || ticket_issue_epoch[4] ||
client_resume_key[32] || reserved[20]`, with the epoch encoded big-endian
and reserved bytes zero. This is a distinct alternative to the envelope and
80-byte plaintext above; it is not wire-compatible and MUST NOT be mixed
with it. The field called `transport_epoch` in the sample should be named
`ticket_issue_epoch`: packet transport epochs and ticket age/rotation epochs
are separate protocol values and need separate checks.

Unlike the preceding fixed-zero-nonce-under-master-key sketch, a fresh
24-byte nonce for every encryption is a valid XChaCha20-Poly1305 approach
when generated by a cryptographically secure, failure-reporting RNG. Random
nonces are not strictly unique: for independent uniform 192-bit nonces, the
collision probability after `N` tickets under one key is approximately
`N(N-1)/2^193` while small. Deployments still need issuance limits and a
collision-risk target, and MUST fail ticket creation if secure randomness
fails. A `void randombytes(...)` declaration that provides no observable
failure status is insufficient unless its documented contract guarantees
fail-stop behavior on RNG failure. The nonce is transmitted in clear and
used by AEAD; tampering with it must cause authentication failure.

This alternative encrypts the connection ID and issue epoch and proposes no
external AAD. After successful authentication, the server can compare the
decrypted connection ID to the outer frame's connection ID, validate the
ticket issue epoch, and check all 20 reserved bytes are zero before using the
resume key. It still needs explicit binding for protocol version, suite,
server/service identity, and any key identifier; these can be carried in
authenticated plaintext or AAD, but must be fixed in the schema. AEAD success
alone does not prove client possession of the separately held
`K_client_resume`; the outer packet authentication must provide that proof.

The sample's `current_epoch - ticket_epoch <= 3` rule accepts four epoch
values including the current epoch, not an unambiguous "three-epoch"
lifetime. Define the exact inclusive/exclusive window, epoch duration,
clock/rollover behavior, future-epoch handling, and whether expiry is by
epoch or wall-clock time. Its single `stek_master_key` parameter also leaves
rotation underspecified: once the master key changes, the server cannot
select the old key from this envelope before decryption. Either specify that
key rotation invalidates all outstanding tickets, or add a bounded,
authenticated key selector and define retention/selection without
unbounded trial decryption. Decrypted plaintext and output resume-key
buffers must be wiped on every rejection path.

#### Alternative ticket with authenticated key selector

A further fixed-size candidate adds a four-byte big-endian `key_id` before
the 24-byte XChaCha nonce:

`key_id[4] || ticket_nonce[24] || ciphertext[68] || tag[16]`

The 68-byte plaintext is proposed as
`connection_id[16] || ticket_issue_epoch[4] || client_resume_key[32] ||
reserved[16]`, totaling 112 bytes including the cleartext selector, nonce,
and tag. This supersedes neither the 112-byte `nonce[24] || ciphertext[72] ||
tag[16]` alternative nor the earlier salt/subkey envelope; they are
incompatible layouts and require distinct versioned formats or an
unambiguous outer discriminator. The `transport_epoch` label in the sample
should be `ticket_issue_epoch` unless it truly refers to packet-key epoch;
the two concepts MUST remain distinct.

The selector can let a server or trusted proxy choose a bounded historical
STEK before decryption. It is attacker-controlled until authentication
succeeds, so lookup MUST be bounded and must not trigger unbounded key trials.
Bind the exact cleartext selector and a fixed domain separator into AEAD AAD.
The AAD should also bind any required protocol version, suite, service/key
scope, and other context, either directly or through an explicitly specified
authenticated plaintext. Key IDs must not be reused for a different key
while tickets referencing the old key may remain valid. Define active and
verification-only key lifetimes, unknown/revoked key behavior, and whether
rotation invalidates tickets. The key ID is a locator, not secret material
or proof of ticket validity.

The shown domain string `SPEC-LATTICE-WIRE-02/STEK` is 25 bytes; appending
the four key-ID bytes produces 29 bytes of AAD. Its length and exact bytes
must be checked by KATs. The sample's `(uint32_t)(current_epoch -
ticket_epoch) <= 3` rule is not by itself a safe rollover policy: it accepts
the current epoch and three prior values, but modulo arithmetic cannot
distinguish a recent prior epoch from a value almost one full 32-bit cycle
in the future. Define bounded serial-number arithmetic, restrict comparisons
to a range strictly smaller than half the `uint32_t` space, reject
unacceptable future issue epochs, and specify how epoch wrap is avoided or
handled. A monotonic non-wrapping wider internal epoch or a key-generation
identifier may be preferable.

The revised generator proposal correctly makes RNG failure observable and
requires all five generator arguments. In this repository, however, include
the actual PQClean `randombytes.h`: it declares an `int`-returning function
and maps the name through `#define randombytes PQCLEAN_randombytes`. A
standalone declaration must not create a mismatched or unresolved symbol.
Check the return before sealing; on failure, wipe the plaintext and the
entire partially written output ticket, then return an explicit error.
`std::abort` is not an appropriate normal error path. The revised five-arg
check fixes the earlier out-of-bounds `info[4]` access, but
`ExtractStekKeyId` must still validate the complete ticket length, and the
extracted ID remains only an untrusted bounded lookup hint.

The latest complete validator improves several of these points: fixed-extent
spans make the buffer sizes explicit at the C++ API, the resume-key output
is wiped on entry, reserved padding is checked, the caller-supplied expected
key ID is compared with the ticket selector, and RNG failure wipes the
partially constructed ticket. These checks do not replace valid-memory
preconditions: `std::span<T, N>` does not prove that an arbitrary pointer used
to construct it points to `N` live bytes. Node-API must validate Buffer
lengths before constructing spans, and non-Node callers must satisfy the
span constructor's range requirements. Null pointers must not be passed to
the initial output wipe.

The OR-accumulated padding check has fixed work independent of which padding
byte first differs, but that alone does not make the full validator
constant-time: key-ID mismatch, AEAD failure, connection mismatch, epoch
failure, and distinct returned statuses can still be distinguishable. Use
uniform externally visible failure behavior where ticket validation is
remotely observable.

Including the repository's `deps/mlkem512/common/randombytes.h` is the
right way to use its `int`-returning `randombytes` macro/API; do not redeclare
it independently. The new generator wipes the complete output ticket on RNG
failure, addressing the previous partial-output issue. However, the validator
still does not perform keyring selection itself: `expected_key_id` and the
matching key must come from a bounded trusted lookup using the untrusted
ticket selector. The equality check before AEAD is only a local consistency
check; the key ID is authenticated by successful AEAD verification because
it is included in AAD.

The revised epoch expression,
`static_cast<int32_t>(current_epoch - ticket_epoch)`, is not portable RFC
1982 arithmetic in standard C++: converting an out-of-range `uint32_t` to
`int32_t` is implementation-defined. Define the half-range algorithm using
explicit unsigned comparisons, or use a portable well-specified
representation, and enforce the serial-number precondition that all relevant
epoch distances are strictly less than `2^31`. Otherwise values separated by
half a cycle are ambiguous. The wrap example demonstrates one desired
near-wrap case but does not prove that precondition or reject every ambiguous
future value.

Tests should include RNG failure and full output-ticket wiping, unknown and
rotated key IDs, modified key ID/AAD, bad tag, mismatched connection ID,
nonzero reserved bytes, future/stale/half-range/wrap-boundary epochs, valid
opening, null/invalid output handling at the wrapper boundary, and output
zeroization. Ticket generation/opening belongs in the trusted server
component; a client carries the opaque bytes and proves possession
separately using its resume key.

The accompanying `test/test_stek_v2.mjs` proposal covers useful paths:
five-argument validation, ticket length, successful generation/opening,
cleartext key-ID extraction, AAD/body tampering, connection-ID mismatch,
and a current-plus-three epoch window across a uint32 wrap. It is not
currently runnable because this repository has no v2 addon target or
ticket-management exports. There are also test/API mismatches to resolve
before adopting it: the shown `validateStekTicket` wrapper returns an object
with `status: InvalidLength` for a 111-byte ticket, whereas the test expects
the call itself to throw `RangeError`; choose and consistently test one
contract. The tests do not cover RNG failure, unknown/rotated key selection,
wrong master key, nonzero authenticated padding, or resume-key output
zeroization. `extractStekKeyId` is tested only on a valid ticket, not on short
or malformed inputs. Add validator-result tests only after the wrapper's
failure-status contract and generic-versus-detailed error exposure are
decided.

The rollover examples do demonstrate the intended unsigned subtraction for
the specific sequence `0xFFFFFFFE -> 0 -> 3` (ages 2 and 5). They do not
establish that arbitrary modular comparisons are unambiguous: a 32-bit
counter alone cannot distinguish epochs separated by a full cycle, nor
values on the ambiguous side of the serial-number half-range. Define a
strict operational epoch bound below `2^31`, reject future epochs according
to that model, and preferably prevent internal epoch wrap; retain explicit
boundary tests on both sides of wrap.

The proposed `LatticeConnection` constructor test that passes a
`stekMasterKey` and expects a random 112-byte ticket to throw MUST NOT be
added as a client API test: it would codify the unsafe client-side STEK
exposure described above. A random ticket primarily exercises AEAD
authentication failure; it does not specifically test an expired ticket,
because expiration can only be evaluated after authenticating and decrypting
a well-formed ticket. Ticket-open tests belong on the trusted server-side
ticket validation API. They should separately cover a modified tag/ciphertext,
an authenticated ticket with an expired time/epoch, connection or suite
binding mismatch, malformed reserved fields, and successful opening of a
valid fixture, while verifying that rejected plaintext and resume-key output
are wiped. The current repository still has no v2 addon or
`test/test_v2.mjs`, so no executable test was added.

### 4.1 Proposed STEK rotation lifecycle

The current proposal uses one-hour STEK epochs, two-hour ticket validity,
60-second clock-skew tolerance, and an eight-slot ring indexed by
`ticket_issue_epoch & 0x07`. The intended acceptance window retains
`E-3` through `E+1`, with `E` active for minting; the other retained keys
are verification-only. These are design parameters, not protocol constants.
Workers MUST mint only with the active epoch key. The key selected by the
cleartext ticket issue epoch is authenticated by ticket AEAD; a mismatch
causes authentication failure. No trial-decryption sequence is required.

The updated provisional ticket envelope carries its 4-byte issue epoch and
12-byte ticket salt. The issue epoch selects the STEK directly and MUST be
authenticated as ticket AEAD associated data together with the outer
connection ID. Any cleartext selector is untrusted until that authentication
succeeds. The header's transport epoch remains distinct from this ticket
issue epoch.

#### Per-ticket AEAD key and salt proposal

The 12-byte wire field is a fresh CSPRNG-generated `ticket_salt`, not the
AEAD nonce itself. Derive a 32-byte one-use ticket key as:

`K_ticket = SHAKE256("SPEC-LATTICE-WIRE-02/KDF/TICKET-SUBKEY" || connection_id || uint32_be(ticket_issue_epoch) || ticket_salt || STEK_epoch, 32)`

The label is 38 ASCII bytes without a NUL terminator. All context fields have
fixed widths. Encrypt the 80-byte ticket plaintext with IETF
ChaCha20-Poly1305 under `K_ticket`, using the fixed 12-byte all-zero nonce;
the result is the 80-byte ciphertext and 16-byte tag. The salt, connection
ID, issue epoch, and STEK all affect the derived key, so a repeated salt for
the same connection and issue epoch repeats `K_ticket` and its fixed nonce.
Because a random collision may not be detectable without retaining per-ticket
state, implementations MUST bound issuance per context to a stated collision
risk rather than assume collisions can be detected statelessly.

For independent uniform 96-bit salts, collision probability for `N` tickets
sharing the same `(STEK_epoch, connection_id, ticket_issue_epoch)` is
approximately `N(N-1)/2^97` while that probability is small. This is a
birthday bound, not a deterministic uniqueness guarantee; deployments MUST
set per-key/per-connection issuance limits appropriate to their risk target
and fail ticket minting if the CSPRNG fails. Across different connection IDs
the derived keys also differ when those IDs differ, but this does not
increase the salt's guaranteed entropy or replace the need to analyze
repeated contexts. The KDF output collision probability is additional and
negligible at ordinary volumes, but belongs in a formal bound.

An optional restart-scoped variant is under consideration in Section 8.1. It
adds a server-held boot identifier to the ticket-subkey KDF context; it is
not transmitted on the wire and is not part of the client-resume KDF. A
deployment must use one identifier consistently across every worker sharing
the same replay-state domain. Rotating it invalidates tickets minted under
the previous value and therefore requires clients to perform a fresh
handshake.

The proposed eight-slot ring is intended to hold the five accepted issue
epochs `[E-3, E+1]` and three unused guard slots. This capacity avoids modulo
aliasing among five consecutive epochs, but does not itself prove the epoch
window. The lifetime/clock-skew boundary arithmetic and exact clock used for
ticket validation must be specified and tested before claiming that
`[E-3, E+1]` is sufficient. Ring slot reuse MUST occur only after the prior
epoch is no longer accepted, and key readers need safe publication/lifetime
management while slots rotate.

The submitted C++ ring is illustrative only. Expressions such as
`current_active_epoch + 1` and `(ticket_issue_epoch + 3) -
current_active_epoch` can wrap as `uint32_t`; epoch exhaustion and
boundary-safe comparisons must be specified. Returning a pointer to a slot
key is unsafe if rotation can overwrite that slot while a worker is
decrypting. Implementations need synchronized key publication and lifetime
management (for example, immutable key snapshots with defined reclamation),
not just modulo indexing. Lookup uses `ticket_issue_epoch`, never
`transport_epoch`.

The proposed ratchet derives an epoch STEK and the next chain key from the
current 32-byte chain key:

| Operation | Domain label (ASCII, no NUL) | Length | Context | Secret | Output |
|---|---|---:|---|---|---|
| Epoch key | `SPEC-LATTICE-WIRE-02/KDF/STEK-EPOCH-KEY` | 39 | `uint32_be(epoch)` | `CK_epoch` (32 B) | `STEK_epoch` (32 B) |
| Chain advance | `SPEC-LATTICE-WIRE-02/KDF/STEK-CHAIN-ADV` | 39 | `uint32_be(epoch)` | `CK_epoch` (32 B) | `CK_(epoch+1)` (32 B) |

These are proposed labels and inputs; they require exact SHAKE-256 output
length definitions and known-answer vectors. On an advance, the implementation
derives the needed next key material, securely erases the consumed chain key,
and overwrites a ring slot only after its old key is no longer needed for any
acceptable ticket. Missed epochs require advancing and erasing every
intermediate chain key; startup, crash recovery, epoch rollback, and
multi-worker synchronization must be specified. Restoring an old chain-key
snapshot can regenerate retired keys and violate the intended erasure
property, so ratchet state needs rollback-resistant persistence or a secure
rebootstrap procedure.

This one-way chain can provide past-key protection against compromise of a
later chain state only if prior chain keys and retired STEKs were actually
erased. It does not provide post-compromise recovery: compromise of the
current chain key permits deriving future chain keys and epoch STEKs. A
cluster-wide chain key also means compromise of a worker holding it exposes
future cluster keys. These limits MUST be reflected in the security claims.
The sample `volatile` wipe loop is not a suitable implementation
requirement; implementations SHOULD use a vetted secure-wipe primitive.

## 5. Key separation and packet protection

The final key schedule MUST use reviewed, domain-separated derivations and
MUST specify exact byte strings, lengths, and integer encodings. It MUST
derive distinct keys for:

- handshake request and response protection;
- resumed client-to-server and server-to-client traffic;
- each direction's nonce/IV material;
- separate epochs and protocol purposes.

The schedule MUST bind the negotiated protocol version, packet type or
purpose, epoch, and connection context as appropriate. Reusing an AEAD key
and nonce pair is forbidden.

The current proposed KDF registry is domain-separated SHAKE-256 over the
exact ASCII label and fixed-width inputs in the explicitly specified order;
labels have no NUL terminator. The client-resume derivation is:

`SHAKE256("SPEC-LATTICE-WIRE-02/KDF/HANDSHAKE-RESUME" || connection_id || uint32_be(ticket_issue_epoch) || ticket_salt || ss, 32)`

An alternative handshake KDF bifurcates from the same ML-KEM shared secret
and transcript hash:

`handshake_context = mlkem_shared_secret || transcript_hash` (64 bytes)

`HANDSHAKE_KEY || HANDSHAKE_IV = SHAKE256("SPEC-LATTICE-WIRE-02/KDF/HANDSHAKE-KEY" || handshake_context, 56)`

`K_client_resume = SHAKE256("SPEC-LATTICE-WIRE-02/KDF/RESUME-KEY" || handshake_context, 32)`

The first label is 38 ASCII bytes and the second is 35 bytes (not 34); the
full inputs are therefore 102 and 99 bytes respectively. The 56-byte
handshake output splits into a 32-byte XChaCha20-Poly1305 key and 24-byte
nonce. This is a separate candidate from the existing
`HANDSHAKE-RESUME` derivation, which also includes connection ID, ticket
issue epoch, and ticket salt. A protocol version must select one exact
construction and define how the client and server obtain identical values;
the candidates cannot be interchanged silently. Each derivation needs
known-answer tests and cryptographic review.

The directional-key candidate derives each direction separately using the
domain label, `K_client_resume`, `connection_id`, `server_boot_id`,
`uint32_be(transport_epoch)`, and `direction_flag`. Its output depends on
the selected AEAD suite: 44 bytes for IETF ChaCha20-Poly1305 (32-byte key
plus 12-byte base IV), or 56 bytes for XChaCha20-Poly1305 (32-byte key plus
24-byte base nonce). Candidate identifiers `0x0001` and `0x0002` have been
proposed respectively. The exact suite identifier and byte-string encoding
must be bound into authenticated negotiation and the KDF; peers MUST NOT use
the same derivation context with different output lengths or nonce
interpretations. Merely storing a local `cipher_suite` value does not
negotiate or authenticate the suite.
`direction_flag` is `0x00` for client-to-server and `0x01` for
server-to-client. This replaces the earlier combined 64-byte-key/24-byte-IV
output proposal. `server_boot_id` is a public 16-byte identifier, unique
with overwhelming probability per server boot and shared by workers using
the same replay-state domain. The handshake must securely convey it to the
client. This is a candidate and requires known-answer vectors for each
direction and independent cryptographic review. It is the same boot-scoped
identifier used by the optional ticket-key variant when that variant is
enabled; deployments must not use divergent values for one session.

The ticket-subkey derivation is:

`K_ticket = SHAKE256("SPEC-LATTICE-WIRE-02/KDF/TICKET-SUBKEY" || connection_id || uint32_be(ticket_issue_epoch) || ticket_salt || STEK_epoch, 32)`

It uses the 38-byte ASCII label `SPEC-LATTICE-WIRE-02/KDF/TICKET-SUBKEY`
and the fixed zero IETF nonce for ticket AEAD. The label byte lengths are:

| Label | Byte length |
|---|---:|
| `SPEC-LATTICE-WIRE-02/KDF/HANDSHAKE-RESUME` | 41 |
| `SPEC-LATTICE-WIRE-02/KDF/TICKET-SUBKEY` | 38 |
| `SPEC-LATTICE-WIRE-02/KDF/STEK-EPOCH-KEY` | 39 |
| `SPEC-LATTICE-WIRE-02/KDF/STEK-CHAIN-ADV` | 39 |
| `SPEC-LATTICE-WIRE-02/KDF/DIRECTIONAL-KEYS` | 41 |
| `SPEC-LATTICE-WIRE-02/KDF/DIRECTION-IV` | 37 |

The restart-scoped ticket variant proposed in Section 8.1 inserts
`server_boot_id` (16 bytes) between `ticket_salt` and `STEK_epoch` in this
derivation. That variant is server-local and does not change the ticket
envelope, but all workers that mint or open tickets in one replay-state
domain MUST use the same boot identifier. The deployment mode and exact
derivation variant must be fixed before interoperability is claimed.

The supplied registry's directional-key length (40) and direction-IV length
(36) are incorrect. The handshake response MUST deliver the ticket salt and
issue epoch consistently with these derivations and bind them to the
authenticated handshake transcript. This registry is still provisional and
does not yet define the complete handshake KDF or `K_pop` usage.

For resumed datagrams, the current nonce candidate is:

`nonce = direction_iv XOR (0x00000000 || uint64_be(SeqNo))`

The 12-byte nonce is derived and is not transmitted in the current `0x0004`
candidate. The explicit `uint32_be(random_salt) ||
uint64_be(packet_seq_no)` construction is superseded. Sequence numbers MUST
NOT wrap under a key. Epoch rollover MUST derive fresh traffic keys before
sequence exhaustion and MUST define how old and new epochs overlap. The
key/IV derivations must ensure that nonces are never reused under the same
directional AEAD key, including after restart or epoch rollover.

Packet keys SHOULD be stable within a bounded epoch rather than advanced as a
single hash chain on every datagram. This allows packet loss and reordering;
the sequence number and replay window provide per-packet uniqueness and
replay filtering. A separate epoch key-update schedule is still required to
bound key lifetime and define compromise recovery. Hashing a key forward only
protects past keys when old state is securely erased; it does not provide
post-compromise recovery for future traffic.

The exact AAD for every packet type MUST be its validated fixed header and
the explicitly enumerated type-specific cleartext fields. The tag location,
payload location, and frame-length equation MUST be specified for each type.

## 6. Provisional wire layout, replay, and concurrency

The provisional resumed-transport layout is:

| Offset | Size | Field |
|---:|---:|---|
| 0 | 32 | Header described in Section 3 |
| 32 | 4 | Ticket issue epoch (`uint32_be`) |
| 36 | 12 | Ticket salt (`ticket_salt`, CSPRNG bytes) |
| 48 | 80 | Encrypted ticket plaintext |
| 128 | 16 | Ticket AEAD tag |
| 144 | 12 | Outer packet explicit nonce |
| 156 | variable | Encrypted payload |
| `156 + payload_length` | 16 | Trailing outer AEAD tag |

For this resumed-transport layout, the UDP datagram length itself can
determine the payload length:

`payload_length = datagram_length - 172`

The receiver MUST first reject datagrams shorter than 172 bytes and apply a
configured maximum datagram size before deriving this value. This equation
does not define the separate handshake or handshake-response layouts.

The inner ticket plaintext and encrypted envelope are defined provisionally
in Section 4. The outer 16-byte `connection_id` MUST match the inner ticket's
16-byte `connection_id` after ticket authentication. The
ticket envelope is 112 bytes in total: issue epoch, ticket salt, 80-byte
ciphertext, and 16-byte ticket tag.

The proposed ticket AEAD AAD is the 20-byte span `[16, 36)`, containing the
outer `connection_id` and ticket issue epoch. The ticket salt at `[36, 48)`
is included in the per-ticket key derivation; the ticket AEAD uses a fixed
all-zero 12-byte nonce. The proposed outer
packet AAD is the complete cleartext prefix `[0, 156)`, containing the header,
ticket issue epoch, ticket salt, encrypted ticket and its tag, and outer
packet nonce. Both boundaries remain provisional pending final review.

### 6.1 Proposed two-stage receive pipeline

The intended receive ordering is:

1. Bound the datagram length and validate the v2 version and resumed frame
   type before reading any other field. Reject
   `packet_seq_no >= UINT64_MAX - 64` before cryptography.
2. Read `ticket_issue_epoch` and `ticket_salt`, select that issue epoch's
   STEK, derive `K_ticket` (including `server_boot_id` when the
   restart-scoped variant is configured), then authenticate/decrypt the
   80-byte ticket ciphertext with the fixed zero nonce and 20-byte ticket
   AAD `[16, 36)`.
3. Validate ticket timestamps, flags, and zero reserved bytes. Compare the
   authenticated inner `connection_id` with the outer 16-byte routing tag.
   Reject a `transport_epoch` outside the permitted current/previous window.
4. After ticket authentication and connection-ID binding, perform a
   read-only replay inspection using the authenticated connection ID and
   validated transport epoch. Do not allocate or mutate replay state here.
   A known stale or duplicate sequence MAY be dropped before Stage 2; a cold
   miss or apparent bucket saturation proceeds to Stage 2.
5. Derive the receive-direction packet key from `client_resume_key`,
   `connection_id`, and `transport_epoch` using the proposed Section 5 KDF.
   Verify that the outer explicit nonce equals the direction-IV/sequence
   construction, then authenticate/decrypt the payload using the exact
   156-byte AAD.
6. Atomically commit the sequence only after Stage 2 succeeds. Fail-closed
   admission, a duplicate, or a stale sequence at commit rejects the packet;
   if decryption was in-place, wipe plaintext before rejection. Expose
   plaintext only after the commit succeeds.

Ticket decryption authenticates the ticket contents but does not establish
client proof of possession. Only successful outer packet authentication under
keys derived from the separately client-held `K_client_resume` provides that
proof. Implementations MUST NOT trust a cleartext routing tag, epoch, or
sequence number as authenticated for acceptance or state mutation until the
relevant AEAD succeeds. The narrowly scoped read-only stale/duplicate reject
described above is not an authenticated acceptance decision.

The attached implementation sketch is illustrative and MUST NOT be copied
as-is. Monocypher's `crypto_aead_unlock` is the XChaCha20-Poly1305 one-shot
interface and takes a 24-byte nonce; passing the 12-byte v2 explicit nonce
would be an invalid read. The 12-byte outer nonce requires the IETF interface
(`crypto_aead_init_ietf` plus `crypto_aead_read`) or another API explicitly
specified for 96-bit nonces. The same API/nonce-size check is required for
ticket encryption. The sketch also labels a derivation SHAKE-256 while calling
an unspecified BLAKE2b function, so it does not define a conforming key
schedule. The earlier worker/boot-salt/counter nonce construction is
superseded by the random ticket salt and per-ticket subkey proposal in
Section 4.1; the optional restart-scoped KDF context is a separate candidate
in Section 8.1. This changes the nonce risk to probabilistic salt collisions
under repeated `(STEK, connection_id, issue_epoch)` contexts; it does not
provide deterministic uniqueness. All decrypted ticket/key buffers MUST be
wiped on every success and failure path, including ticket-authentication
failure.

The provisional 2-byte frame type assignments are `0x0001` for handshake
traffic and `0x0002` for resumed transport. The candidate server response
uses `0x0001` and carries the protected ticket and client secret, but no
request/response subtype or response layout has been specified yet.

This layout follows the 112-byte ticket envelope and 12-byte outer nonce:
payload begins at byte 156, and the minimum complete frame is 172 bytes
including the trailing outer tag. Earlier payload offsets 124 and 140 and the
96-byte envelope are superseded by this provisional layout. The header's
16-byte identifier matches the inner `connection_id`; the ticket salt and
issue epoch are carried in the ticket envelope and bind into the resume KDF.
The table remains informative and implementations MUST NOT claim conformance.

Replay state MUST be scoped to the authenticated session, direction, and
epoch. A read-only inspect MAY reject a known stale or duplicate sequence
after Stage 1 ticket authentication and connection-ID binding, but before
Stage 2 payload authentication. It MUST NOT allocate or mutate state, and
MUST NOT be used as evidence that the packet is accepted. New-session
admission and replay-state mutation MUST occur only after Stage 2 succeeds.
The ticket is replayable and does not itself prove possession of
`K_client_resume`; the tentative check is an optimization, not client
authentication.

The replay algorithm MUST implement a 64-packet reordering window and define
behavior for too-old packets, duplicates, concurrent arrivals, epoch changes,
and sequence exhaustion. A sequence below the current maximum is eligible
only if its distance is less than 64 and its bitmap bit is clear. The bitmap
and sequence floor MUST be updated as one logically atomic commit; separate
unsynchronized updates can admit replays or reject valid reordered traffic.
A lock-free implementation is not a protocol requirement. Any implementation
using atomics MUST provide safe ownership, publication, reclamation, and
slot-reuse semantics; returning an unprotected pointer to mutable session
state is not sufficient.

An authenticated packet that loses a race at replay commit MUST NOT expose
plaintext to the caller. If decryption occurred in place, the plaintext bytes
MUST be erased before reporting rejection.

### 6.2 Provisional two-phase 64-packet window

The supplied replay-filter proposal uses one logically atomic state
`(seq_floor, window_mask)`. Under its stated mapping, `seq_floor` is the
lowest sequence represented by the window: bit 0 represents `seq_floor`,
and bit 63 represents `seq_floor + 63`. A sequence below the floor is stale;
one in that range is eligible only when its bit is clear.

For a sequence `S` at least 64 above the current floor, the proposed
representation advances the floor to `S - 63`, shifts the old mask right by
the floor advance, and sets bit 63 for `S`. This preserves the bit-to-sequence
mapping, including when the advance is at least 64 (in which case no old bit
remains in the window). This is not equivalent to the accompanying prose
that says to advance the floor to `S`, shift left, and set bit 0; that prose
uses incompatible floor/bit semantics and MUST be corrected before an
implementation or test vectors are normative.

The intended processing is a read-only tentative inspection followed by
authentication and a compare-and-swap commit. Concurrent packets may both
pass inspection; only the first commit of a given sequence may succeed. A
losing authenticated packet MUST have any in-place plaintext erased before
rejection. The sequence committed MUST be the same sequence authenticated
as part of the outer AEAD AAD. Authentication failure MUST leave the replay
state unchanged.

The supplied C++ is a design sketch, not a conforming implementation:

- `inspect()` checks `MAX_FORWARD_JUMP`, but `commit_after_auth()` does not.
  If that limit is retained, commit MUST enforce it on every CAS-loop
  iteration using the latest observed state; inspection alone cannot enforce
  an invariant under concurrent floor advances.
- `std::atomic<ReplayState>` does not by itself guarantee lock-free
  128-bit operations or map to `cmpxchg16b` on every C++20 compiler/target.
  A lock-free claim requires a supported-platform contract and verification;
  otherwise use a correct fallback and retain the same atomic state
  transition semantics.
- A tentative inspection MUST NOT run before ticket authentication and
  connection-ID binding. After Stage 1 it may inspect an existing state, but
  MUST NOT create session state or make an acceptance decision. If the state
  cannot be selected safely, skip the optimization and proceed to Stage 2.
  This requirement also means opaque tickets alone do not make replay
  processing stateless.
- The pipeline's `std::byteswap` use is C++23, not C++20. Wire integers
  require explicit endian conversion compatible with the project's
  configured language standard.

Initial floor semantics, maximum forward jump policy, epoch transition and
reset behavior, atomic-state ownership/reclamation, and persistence or
coordination across workers and restarts remain unresolved. The 64-bit
atomic window is a per-process/per-session defense unless deployment-wide
state is specified; it does not prevent duplicate acceptance by independent
workers or after state loss.

### 6.3 Atomic ordering and x86-64 implementation notes

The proposed successful compare-exchange uses acquire-release ordering and
relaxed ordering on failure. In the C++ memory model, release orders
operations sequenced before a successful commit with respect to an acquiring
operation that observes the committed state; acquire constrains operations
sequenced after a successful operation. A relaxed failure provides no such
synchronization, even though the expected value is updated for the retry.
These orders do not, by themselves, publish a decrypted buffer to an
unrelated consumer: buffer ownership and any handoff to that consumer still
require an appropriate synchronization mechanism.

On x86-64, a compiler/standard-library implementation may lower a 16-byte
compare-exchange to `lock cmpxchg16b` when the target supports it. The
instruction compares the memory operand against `RDX:RAX` and, on a match,
writes `RCX:RBX`; on a mismatch it loads the observed value into `RDX:RAX`.
With the state laid out as two consecutive 64-bit words on little-endian
x86-64, these pairs correspond to `(window_mask, seq_floor)` and
`(desired.window_mask, desired.seq_floor)`, respectively. The memory operand
must meet the instruction's 16-byte alignment requirement. The C++ atomic
implementation remains responsible for honoring the type's alignment and
atomicity.

Neither the C++ standard nor `std::atomic<ReplayState>` guarantees that this
operation is lock-free or emits that instruction. Toolchain target flags,
standard-library implementation, CPU feature support, and ABI all matter;
unsupported or non-lock-free cases may use a runtime helper. Generated
assembly must be inspected for the exact compiler, flags, and target rather
than treated as protocol behavior.

The submitted disassembly is illustrative, not verified output. In
particular, x86 variable-count `SHL`/`SHR` instructions read their count from
`CL`; the shown sequence uses `CL` while `RCX` is also described as holding
the desired mask, without preserving the intended delta/shift count. It
therefore does not establish correct register allocation or executable
assembly. Register assignments and save/restore behavior also vary by ABI
(including Windows x64 versus System V).

Performance figures for locked 16-byte compare-exchange, cache-line
contention, NUMA traffic, and weak versus strong compare-exchange are
hardware- and workload-dependent and are not protocol guarantees. A locked
operation on cacheable memory typically obtains exclusive cache-line
ownership; it does not imply a bus lock in the ordinary aligned case.
`compare_exchange_weak` may be useful in a retry loop, but it can fail
spuriously and does not guarantee fewer instructions or lower latency than
`compare_exchange_strong` on a given implementation. Alignment and
cache-line padding can reduce certain penalties, at a memory-footprint cost,
but their benefit should be measured with the actual per-connection layout
and workload.

### 6.4 Audit of the integrated C++ header sketch

The updated `lattice_wire_v2.hpp` sketch fixes some earlier issues: it
provides C++20 byte-swap helpers, adds a maximum-size check, wipes the ticket
plaintext buffer on ticket-authentication failure, and includes the STEK as
a BLAKE2b key in the ticket-subkey derivation. It remains unsuitable as a
reference implementation, for these reasons:

- The latest correction changes the sequence check to
  `seq_no >= UINT64_MAX - 64`, matching the proposed exclusive ceiling, and
  specifies `memcpy`-based big-endian readers for parsed fields. These
  changes address the previously identified boundary and unaligned integer
  load defects if applied consistently to the full ingress function. The
  helper's byte-pointer conversion for serializing a local epoch is not an
  unaligned integer load, but an explicit byte-wise big-endian serializer
  would be clearer and less error-prone.
- The ticket-subkey code is still not the specified KDF. It calls
  `crypto_blake2b_general` with the STEK as the BLAKE2b key, but omits the
  `TICKET-SUBKEY` domain label from the hash input. BLAKE2b keyed hashing is
  not interchangeable with the registered SHAKE-256 construction. The
  `server_boot_id` is present in the message, but this alone does not resolve
  the primitive/encoding mismatch or within-boot salt collisions.
- Zero-padding a 12-byte IETF nonce to 24 bytes does not make
  Monocypher's XChaCha20-Poly1305 API equivalent to IETF
  ChaCha20-Poly1305. Both ticket and outer payload calls still use
  `crypto_aead_unlock()` with the 24-byte-nonce XChaCha construction, while
  the wire/KDF design specifies 12-byte IETF nonces. The outer explicit
  nonce is also never compared with the expected directional-IV/sequence
  value.
- The function accepts one `current_stek` and uses it for all ticket epochs;
  it does not select or validate a STEK by `ticket_issue_epoch`. The ticket
  issue-epoch window and resumed `transport_epoch` acceptance window remain
  unchecked.
- The ticket timestamp check does not reject `expires_at <= issued_at` or
  unsupported `flags`. Cold replay admission initializes `seq_floor` from
  the incoming sequence rather than enforcing the ticket's
  `initial_seq_floor`.
- The directional receive key is still not derived from
  `K_client_resume`: BLAKE2b uses `DOMAIN_DIR_KEYS` as its key and only
  `connection_id || epoch` as its message. It neither derives the registered
  key/IV outputs nor chooses the client-to-server receive key. It therefore
  does not establish proof of possession of the client-held secret.
- The replay-way key omits direction although replay state is
  direction-scoped. The tentative seqlock still reads mutable way fields
  non-atomically while writers may change them, which is a C++ data race.
  Its boolean result also conflates stale/duplicate detection with a changed
  sequence counter; a changed counter must fall through to authenticated
  processing rather than be treated as replay rejection. `purge_epoch()`
  still `memset`s potentially concurrent state without reader reclamation or
  a safe slot-generation protocol.
- The latest proposal gives a concrete SHAKE-256 replay-index input:
  `DOMAIN_REPLAY_INDEX || connection_id || uint32_be(transport_epoch) || table_seed`,
  squeezes eight bytes, decodes them as little-endian, and masks with
  `0x3FFF`. This resolves the previously open primitive and input-order
  choices at the candidate level, assuming the SHAKE API implements FIPS 202
  SHAKE-256 exactly. The latest proposed tests include expected buckets for
  zero connection ID and zero seed at epochs 0 and 1; Section 8.1 records
  both vectors.
  Implementations must verify those vectors against their selected FIPS 202
  SHAKE-256 API and define the API, output length, byte order, and seed
  lifecycle. The newly supplied handwritten Keccak implementation is not
  suitable for adoption: its Rho/Pi rotation constants do not match the
  FIPS 202 Keccak-f[1600] round mapping, and it absorbs/emits 64-bit lanes
  with native-endian `memcpy`, which is not portable to big-endian hosts.
  Its test helper also uses epoch zero while comparing against the
  epoch-one digest, and its expected digest bytes are reversed relative to
  the SHAKE output byte string. Use a vetted SHAKE-256 implementation and
  verify the explicit vectors in Section 8.1 instead of shipping custom
  sponge code.
  SHAKE-256 is an unkeyed XOF, so the secret seed's inclusion in the
  domain-separated input is essential to blinding bucket selection.
- A proposed 1,350-byte maximum UDP payload is larger than the IPv6 minimum
  MTU permits without fragmentation: with only the base 40-byte IPv6 and
  8-byte UDP headers, the maximum UDP payload at an IPv6 MTU of 1,280 bytes
  is 1,232 bytes. A 1,200-byte UDP-payload cap is a conservative default
  under those assumptions; for the 172-byte `0x0002` framing overhead, it
  leaves at most 1,028 bytes for application payload. Extension headers,
  tunnels, or smaller path MTUs require a lower configured cap or path-MTU
  discovery. This is a recommended deployment default, not a universal
  guarantee against fragmentation on every path.
- The latest code corrects the sequence ceiling to `>=` and shows an
  explicit wipe on Stage 2 failure. Those changes address the previously
  identified issues only if applied to the complete function and after
  validated lengths; they do not resolve the remaining AEAD, KDF, key
  selection, or replay-state correctness findings.

The snippet only implements a `0x0002` receive path; it does not implement
the candidate `0x0001` or `0x0003` handshake flows. No code from this header
should be copied into a production implementation without resolving these
issues, selecting the exact primitives/APIs, providing race-free replay
state and safe epoch/key lifetimes, and testing the resulting implementation.

## 7. Resource and error handling

Receivers MUST validate version, packet type, lengths, epoch policy, and
maximum datagram size before indexing type-specific fields or invoking
cryptography. Unknown tickets, expired tickets, failed authentication, and
replay rejection SHOULD be externally indistinguishable where practical.
Network-facing implementations SHOULD silently drop invalid datagrams rather
than return detailed errors to unauthenticated senders.

Implementations MUST bound ticket decryption and replay work, avoid allocating
unbounded session state from unauthenticated traffic, wipe temporary secrets,
and avoid releasing plaintext until authentication and replay commit both
succeed.

## 8. Decisions required before an interoperable wire specification

The following are intentionally unresolved and MUST NOT be treated as
implementation defaults:

1. Ticket-salt CSPRNG quality and per-context invocation limits for the
   derived-key/fixed-zero-nonce construction, including collision bounds and
   failure handling.
2. Handshake request/response semantics, peer authentication, ML-KEM key
   selection/rotation, exact handshake KDFs, replay/deduplication of
   initiation and early data, response nonce uniqueness (including restart),
   anti-amplification policy, and protected delivery of the ticket and all
   `K_client_resume` derivation inputs.
3. Maximum v2 frame size (the UDP payload, excluding IP and UDP headers)
   and path-MTU/fragmentation policy. A 1,200-byte frame cap is a
   conservative starting point for the IPv6 1,280-byte minimum MTU under
   base-header assumptions, leaving at most 1,028 bytes of application
   payload in a 172-byte-overhead `0x0002` frame. The actual limit must
   account for path extensions/tunnels and `datagram_length - 172` framing
   overhead.
4. STEK ratchet initialization, rollback-resistant persistence/recovery,
   multi-worker synchronization, key retention proven against ticket
   lifetime and skew, expiry/epoch policy, revocation, and supported flags.
5. Exact SHAKE-256 construction/output conventions, transcript binding,
   `K_pop` usage, known-answer vectors, epoch rollover, initial replay-floor
   semantics, and maximum forward-jump policy.
6. Replay-table policy: the candidate three-table epoch ring, fixed-capacity
   bucket layout, keyed index hash, sequence ceiling, fail-closed saturation,
   entry-retention lifetime, ownership, persistence, distributed-worker
   coordination, and restart behavior.
7. Whether records are processed in-place and the API's buffer-ownership
   contract.
8. Denial-of-service controls, rate limits, error side-channel policy,
   handshake deduplication and cache lifecycle, interoperability fixtures,
   review criteria, and supported platforms.

### 8.1 Candidate resolutions under evaluation

The following newer proposals narrow the open questions but do not yet close
them or change the draft's non-normative status.

#### Ticket subkey and random salt

The current candidate derives `K_ticket` with the
`KDF/TICKET-SUBKEY` SHAKE-256 label from the STEK, connection ID, issue epoch,
and a fresh 96-bit CSPRNG `ticket_salt`, then uses an all-zero 12-byte IETF
AEAD nonce. This removes worker IDs, persistent counters, and boot salts
from the nonce construction, but does not make the construction
collision-free: a salt collision under the same
`(STEK, connection_id, issue_epoch)` repeats the ticket key and nonce.
The deployment must define per-context issuance limits, collision-risk
targets, CSPRNG failure behavior, and known-answer vectors for the derivation.

#### Restart-scoped ticket invalidation

Because replay tables are volatile, a restart can erase accepted sequence
state while a persistent or re-derived STEK remains unchanged. One candidate
is to generate a fresh 16-byte CSPRNG `server_boot_id` for each replay-state
domain and insert it between `ticket_salt` and `STEK_epoch` in the
`KDF/TICKET-SUBKEY` input:

`K_ticket = SHAKE256(label || connection_id || uint32_be(ticket_issue_epoch) || ticket_salt || server_boot_id || STEK_epoch, 32)`

The boot identifier separates key-derivation contexts across boots; it does
not make ticket salts unique within one boot. A repeated 96-bit salt under
the same `(server_boot_id, STEK, connection_id, issue_epoch)` still repeats
the derived key and fixed AEAD nonce, with the same birthday-bound collision
risk described above. Per-context issuance limits and CSPRNG failure
handling therefore remain necessary.

The identifier is server-local, not a wire field, and MUST be held only in
protected, memory-locked volatile memory. Rotating it makes tickets minted
under its previous value fail ticket authentication, so clients need a fresh
handshake after replay state is lost. This trades ticket continuity for
restart safety; it does not preserve replay state or tickets across restart.
Multiple workers that share STEKs and replay tables MUST use the same
identifier. The deployment must define CSPRNG and memory-locking failure handling,
shared-memory initialization, crash-dump policy, and which restart events
rotate the identifier. Memory locking alone does not protect against every
crash dump or privileged reader.

#### STEK ring depth

An eight-slot ring indexed by `ticket_issue_epoch & 0x07` is proposed to
retain the five issue epochs `E-3` through `E+1`, with three guard slots.
The ring capacity prevents modulo aliasing within that five-epoch set, but
does not prove that the window itself is sufficient. The specification must
define clock-skew application, ticket mint-time constraints, key acceptance
bounds, and rollover order, then validate the exact boundary math. Epoch
arithmetic must be checked at `uint32_t` boundaries; slot reuse and reader
lifetime must also be specified.

#### Replay-state lookup

The latest candidate replaces shared bucket watermarks with three
epoch-partitioned replay tables. Each table holds state only for one
`transport_epoch`; the active window is proposed as
`[E_current - 1, E_current + 1]`. On advancing from E to E+1, the table for
E-1 is retired and may be wiped/reassigned to E+2 only after E-1 traffic is
no longer accepted. This corrects the earlier rotation wording that paired
the retiring E-2 slot with E+1. Epoch checks and ring indexing must use
checked arithmetic, especially near `uint32_t` limits.

The proposed table has 16,384 buckets, four 64-byte ways per bucket, and
256-byte bucket alignment: 4,194,304 bytes (4.0 MiB) per epoch table and
12.0 MiB for three tables, excluding seeds and other state. These sizes must
be verified with compile-time assertions and measured on each supported ABI.
Read-only lookup may occur after ticket authentication and connection-ID
binding but before outer payload authentication; creation and mutation occur
only after outer authentication. A duplicate may be rejected before the full
outer AEAD cost, while a cold miss still incurs it. Concurrent create-or-
commit must be serialized for the bucket, and a losing packet's decrypted
payload must be wiped. Replay sequence state is direction-scoped; the
proposed way key shown in the attachment omits direction, so a final table
must either include direction in its key or maintain independent
direction-specific state.

The parser candidate rejects `packet_seq_no >= UINT64_MAX - 64`
(`0xFFFFFFFFFFFFFFBF`) before cryptography. This ceiling avoids later
window-floor arithmetic reaching the integer limit, but consumes part of the
sequence space and MUST be enforced consistently by senders and receivers;
key/epoch rollover must happen before the ceiling. The limit is a proposed
wire policy, not only an implementation guard.

The candidate uses fail-closed admission instead of evicting active ways:
use a free way, otherwise reject a new authenticated stream when all four
ways are occupied. This avoids shared-watermark poisoning but exposes a
bucket-capacity denial of service. The proposed idle lease does not make
reclamation replay-safe by itself: an accepted packet may be replayed after
the lease expires while its ticket and transport epoch remain valid. Ways
MUST NOT be reclaimed merely for idleness unless a durable per-connection
floor/tombstone remains through the full replay-acceptance lifetime. New
connection IDs are not guaranteed to hash to another bucket, so re-handshake
is not guaranteed to resolve saturation.

The stricter pinned-way candidate keeps each allocated
`(connection_id, transport_epoch)` entry for the entire time that its epoch
is accepted. A way is reclaimed only when its whole epoch table is retired;
idle-time eviction alone would reopen replay acceptance. This prevents
lease-expiry replay holes but increases the chance of bucket saturation for
the rest of an epoch.

The server-selected connection-ID candidate proposes checking capacity in
the active and next tables before ticket delivery, redrawing when a
candidate bucket has at least three occupied ways, with a bounded attempt
count. It is not a guarantee of non-collision or admission: concurrent
handshakes require atomic capacity reservation, redraws may repeatedly hit
the same bucket, and behavior after attempts are exhausted must be specified.
If this policy is adopted, any capacity reservation must be bounded and
coordinated with the authenticated post-Stage-2 admission path; it must not
be treated as accepted replay state before Stage 2.

#### Tentative replay inspection and bucket concurrency

The latest candidate moves read-only replay inspection to after Stage 1
(ticket authentication and inner/outer connection-ID match) but before
Stage 2 (payload AEAD). This can avoid directional KDF and payload-AEAD work
for an already-known stale or duplicate sequence. Inspection MUST NOT create
or mutate state, and it MUST NOT accept a packet: the sequence number is not
authenticated until Stage 2. A cold miss or apparently full bucket proceeds
to Stage 2; only then may authenticated admission fail closed. Ticket
authentication alone is not proof of possession of `K_client_resume`, and
the changed ordering requires timing-side-channel review. The revised
`tentative_inspect` proposal correctly changes the full-bucket miss case to
proceed to Stage 2, and makes an odd or changed sequence counter fall through
instead of dropping based on an unstable snapshot. This avoids using bucket
occupancy or a contended read as a pre-authentication rejection condition.
It does not establish that forged packets have identical observable latency:
cache state, scan length, contention, and other branches can still differ,
so the stated timing-equivalence claim is not guaranteed by this change.

The follow-up sketch's relaxed `atomic_ref` loads would address data-race UB
for those individual fields only if every concurrently accessing writer also
uses atomic operations on the same objects, all such objects satisfy
`atomic_ref<T>::required_alignment`, and no concurrent access bypasses the
atomic protocol. The previously shown ordinary writer updates would still
race with these loads. Bytewise atomic loads make the connection ID bytes
individually race-free under those conditions, but do not provide a coherent
16-byte snapshot.

Even with atomic accesses on both sides, the snippet does not establish that
the version check reliably detects every mixed snapshot. Relaxed payload
operations plus the shown acquire fence/load are not, by themselves, a
demonstrated C++ memory-order proof of the required seqlock ordering; the
writer-side sequence updates and fences are also unspecified. The assertion
that these operations are necessarily kept within the seqlock boundary, and
the assertion that relaxed operations avoid all expensive barriers on every
target, are too strong. A correct lock-free implementation needs a complete,
formally justified reader/writer ordering protocol and alignment guarantees;
otherwise use a suitable lock or another established race-free snapshot
design. The odd/even and changed-counter fall-through policy is useful only
after both data-race freedom and snapshot validation are proven. Fitting the
counter inside the 256-byte bucket does not establish correctness or lock
freedom. The sketch MUST NOT be copied as implementation guidance.

The current replay-index candidate standardizes on FIPS 202 SHAKE-256 over
the exact 89-byte input
`"SPEC-LATTICE-WIRE-02/KDF/REPLAY-INDEX" || connection_id ||
uint32_be(transport_epoch) || table_seed`, where the label is 37 ASCII bytes,
the connection ID is 16 bytes, the epoch is 4 bytes, and the per-process
CSPRNG seed is 32 bytes. Squeeze exactly eight bytes, interpret them as a
little-endian unsigned 64-bit integer, then mask with `0x3FFF` for the
16,384-bucket index. The seed must be stable across all workers sharing a
replay table; rotating it requires a coordinated table rebuild or reset and
must not silently remap live entries. The submitted function matches this
input order. The following zero-input known-answer vector fixes the framing
and byte-order convention:

| Input field | Value |
|---|---|
| Domain | ASCII `SPEC-LATTICE-WIRE-02/KDF/REPLAY-INDEX` (37 bytes) |
| `connection_id` | 16 zero bytes |
| `transport_epoch` | `00 00 00 00` |
| `table_seed` | 32 zero bytes |
| Absorbed input length | 89 bytes |
| First 8 SHAKE-256 output bytes | `8b 0d e3 3d 08 15 59 db` |
| Little-endian integer | `0xDB5915083DE30D8B` |
| Bucket index (`& 0x3FFF`) | `3467` |

This vector was computed with a FIPS 202 SHAKE-256 implementation. For
comparison, the same inputs with `transport_epoch = 00 00 00 01` produce
digest `e2 cc ab 4b 2c 6c 6b d5`, little-endian integer
`0xD56B6C2C4BABCCE2`, and bucket `3298`. Additional vectors SHOULD cover
nonzero connection IDs and seeds. SHAKE-256 is an unkeyed XOF, so the secret
seed's inclusion in the domain-separated input is essential to blinding
bucket selection. A per-process seed only blinds bucket selection; it does
not prevent table saturation or restore replay state after process restart.
The three-table design and fail-closed admission remain candidates pending
capacity, lifetime, and availability analysis.

The proposed `test/test_v2.cpp` is not currently buildable in this
repository: there is no CMake/CTest configuration, no `lattice_wire_v2.hpp`,
and no `EpochReplayRing`, `process_resumed_datagram_v2`, or related v2
symbols. The existing native test/build path is node-gyp, and the available
ingress API tests a different v1 frame format. The supplied snippet also has
test defects independent of missing APIs: the temporary array passed to
`EpochReplayRing` may leave a dangling seed pointer if retained; the
sequence-number byte injection relies on an undeclared `be64_to_native`
helper; and the saturation assertion expects tentative inspection to reject
a full-bucket miss before Stage 2. That last behavior conflicts with the
documented ordering: an unauthenticated miss/full-bucket observation cannot
reject a packet; the receiver must authenticate first, then fail closed if
authenticated admission cannot reserve replay state. The Stage 1 test does
not verify wiping of any buffer, and the proposed Stage 2 wiping test is only
a comment, not an exercised path. Add end-to-end ingress tests only alongside
the actual v2 implementation, with explicit injectable/testable crypto
fixtures or valid generated tickets and packets; do not treat these
placeholders as evidence for MTU, zeroization, or replay-admission behavior.

The updated `test/test_v2.mjs` proposal improves on the earlier forged-frame
tests by using native sealing helpers to produce valid `0x0003` and `0x0004`
frames. It now covers finite/integral numeric arguments and range boundaries,
fixed Buffer lengths, pre-establishment rejection, handshake authentication
failure and rollback, successful establishment, exact-ciphertext handshake
retransmission, native-returned payload offsets, successful in-place
decryption, duplicate-sequence rejection, and in-place wiping on AEAD/replay
failure. These are useful intended cases, but the suite is not runnable against
the current repository: `binding.gyp` has no `lattice_native_v2` target, and
the current addon does not export `LatticeConnection` or either v2 ingress
method. Do not add it to the default test command until the v2 addon exists.

Several test claims need qualification before implementation. The
`isResumed=true` constructor argument directly sets the phase to
`Established`; it is acceptable only in a test-only fixture or a trusted
resumption constructor whose authentication and ownership contract is
explicit. It must not be a public caller-controlled way to bypass the
handshake state machine. The replay case reseals sequence zero and checks a
duplicate; it does not test a sliding window's advancing floor, acceptance of
out-of-order unseen packets, stale/too-far-ahead boundaries, or concurrent
check-and-commit. Likewise, the pre-establishment test proves the phase gate
returns before AEAD, not that its sealed helper and ingress agree on a
cryptographically reviewed key schedule. The test helpers' shown
`derive_client_rx_material` call omits the suite and direction inputs required
by the candidate KDF; keep those helpers test-only until the exact KDF,
direction/suite binding, and KATs are settled. The subarray case uses native
returned offsets in this revision and verifies decrypted plaintext, but
callers must still respect that the view aliases the mutable datagram buffer.

The accompanying `lattice_native_v2` build/addon proposal is not a drop-in
implementation for this repository. It refers to ML-KEM sources at
`deps/mlkem512/*.c`, while the checked-in implementation is split between
`deps/mlkem512/clean/` and `deps/mlkem512/common/`; it also refers to
`deps/mlkem512/fips202.c` rather than the checked-in
`deps/mlkem512/common/fips202.c`. It assumes `lattice_wire_v2.hpp`,
`derive_client_rx_material`, and the v2 ingress functions already exist;
none are present. The proposed directional sealing helper does not bind a
suite identifier or the direction flag into its shown derivation, although
both are required by the candidate KDF discussion above. Do not select or
ship that helper's key schedule until one exact KDF input encoding and its
known-answer vectors are approved.

The existing `src/addon.cpp` is a Node-API C implementation that registers
the current addon; it does not contain the proposed `Napi::ObjectWrap` or v2
initializer. The v2 binding should therefore be a separate addon entry point
and target, not a second initializer pasted into the existing source. Keep
sealing helpers out of production exports unless they are deliberately
designed as supported APIs; otherwise compile them only into a test-specific
target. The optional public `isResumed` boolean also requires a clearly
defined trusted resumption construction path and must not be treated as
evidence that a handshake was authenticated.

Finally, the proposed config's `NAPI_DISABLE_CPP_EXCEPTIONS` setting is not
by itself an allocation-failure strategy for `std::make_unique`, and the
sample constructor performs that potentially throwing allocation. The addon
must use the repository's configured error-handling conventions or a
non-throwing allocation path, and must preserve the documented failure
semantics. Implement the native v2 frame/state machine and settle its KDF,
suite binding, and resumed-state initialization before enabling the attached
JavaScript tests or claiming they exercise a real C++20 state machine.

#### Native secure secret handles

The current native addon exposes `allocateSecret(buffer)` and
`destroySecret(handle)`. It copies the input Buffer into page-rounded native
memory, locks the pages, and on Linux requires `MADV_DONTDUMP`; allocation
fails explicitly when those protections cannot be applied. The zero-RTT
bindings accept the tagged handle as an alternative to a key Buffer.
`generateMlKem512Keypair({ secureHandle: true })` (or
`generateMlKem512Keypair(true)`) generates the ML-KEM-512 secret key directly
into such an allocation and returns it as an opaque wrapped object alongside
the public-key Buffer. The default call continues to return both keys as
Buffers. Direct generation avoids a V8 secret-key Buffer and its copy, though
the non-secret public key and key-generation randomness still use ordinary
process memory.
`allocateSecret` does not erase the caller's Buffer, so callers should wipe
that copy after transfer. Explicit destruction wipes and releases the native
mapping; the Node-API finalizer is only a fallback. Windows uses
`VirtualAlloc`/`VirtualLock`, which does not provide Linux core-dump exclusion.
These OS controls are best-effort process hardening, not a guarantee against
all persistence paths or evidence of FIPS 140-3 validation.

#### Two-slot epoch key management

`EpochKeyManager` retains current and previous secure key handles, with a
separate replay window per epoch. It uses the existing
`generateMlKem512Keypair({ secureHandle: true })` addon API. To cap the number
of secure allocations at two even during rotation, it destroys the expired
previous handle before allocating the replacement. If allocation fails, the
current epoch remains active, but the older grace epoch has already expired.
An active lease on the previous epoch blocks rotation; leases held during
manager destruction defer wiping until release. Use `acquireEpoch()` across
asynchronous ingress work and always call the returned `release()` method;
`resolveEpoch()` is intended only for immediate synchronous use.

The current wire header has no epoch identifier: bytes 4-7 are `stream_id`.
Do not select an epoch from that field or treat the manager as integrated with
wire-level key selection until an authenticated epoch field and protocol
transition are defined.

#### Standalone ML-KEM shared-secret handles

`encapsulateMlKem512(publicKey[, options])` and
`decapsulateMlKem512(ciphertext, secretKey[, options])` keep returning
Buffers by default. Passing `true` or `{ secureHandle: true }` makes the
shared-secret output a tagged secure handle; decapsulation accepts either a
secret-key Buffer or a secure key handle. Shared-secret outputs are written
directly to their selected Buffer/native allocation, and `MlKem512::Decapsulate`
no longer stages the output in an intermediate stack array. Callers must
explicitly destroy secure shared-secret handles after use. This only protects
the native output allocation; input Buffers and unrelated copies remain the
caller's responsibility.

`deriveZeroRttKey(sharedSecret, headerAad[, options])` derives the exact
per-datagram AEAD key used by the existing Zero-RTT opener. `headerAad` is the
complete 812-byte AAD prefix (fixed header, ML-KEM ciphertext, and nonce), not
just the four-byte stream ID: the existing KDF also binds the destination key
ID and nonce. The result can be a Buffer or secure handle. `sealZeroRttPayload`
accepts the same shared-secret inputs and emits the existing frame layout:
812-byte AAD, ciphertext, then the 16-byte authentication tag. It validates
the header and encoded payload length before encryption. The wire format does
not place the tag before ciphertext.

#### Standalone ChaCha20-Poly1305 bindings

The addon also exposes `aeadLock`, `aeadUnlock`, and `aeadUnlockInPlace` for
raw 32-byte AEAD keys supplied as Buffers or live secure handles. Each accepts
a 12-byte nonce and optional Buffer AAD (including empty, `null`, or omitted
AAD), and uses the existing Monocypher IETF ChaCha20-Poly1305 implementation.
Sealed bytes use `[ciphertext || 16-byte tag]`, matching the payload/tag order
in the Zero-RTT packet after its AAD prefix. `aeadUnlock` returns a new
plaintext Buffer and wipes it before reporting authentication failure.
`aeadUnlockInPlace` mutates the input Buffer only on successful authentication,
wipes the trailing tag, and returns `{ buffer, plaintextLength }`; plaintext
occupies the prefix of that buffer without a copy.

#### Handshake and directional resumed-frame candidates

The candidate assigns `0x0001` to client handshake initiation, `0x0003` to
the server handshake response, and `0x0004` to server-to-client resumed
application data. `0x0002` remains the ticket-bearing client-to-server
resumed frame. These layouts are proposals only; they do not complete the
handshake authentication policy or make the wire format interoperable.

**Client handshake initiation (`0x0001`):**

| Offset | Size | Candidate field |
|---:|---:|---|
| 0 | 32 | Common header; offsets 16-31 carry a fresh 16-byte `client_handshake_id` |
| 32 | 768 | ML-KEM-512 ciphertext |
| 800 | 12 | Client handshake explicit nonce |
| 812 | variable | Encrypted optional early application data |
| end - 16 | 16 | Outer AEAD tag |

The candidate fixes the header sequence number to zero and sets the minimum
datagram size to 828 bytes. The client encapsulates to a server ML-KEM-512
public key, derives 44 bytes with
`SHAKE256("SPEC-LATTICE-WIRE-02/KDF/HANDSHAKE-C2S" ||
client_handshake_id || uint32_be(client_epoch_hint) || ss, 44)`,
and splits them into a 32-byte key and 12-byte IV. The nonce is the IV when
the sequence is zero, and the proposed AAD is `[0, 812)`, including the
ciphertext and nonce. The label is 38 ASCII bytes without a terminator.
The meaning of `client_epoch_hint`, server public-key selection/rotation,
and peer authentication remain undefined; the hint MUST NOT silently select
an unauthenticated server key.

**Alternative compact client initiation (`0x0001`, not wire-compatible):**

A later proposal replaces the preceding 32-byte common-header initiation
with a fixed 794-byte frame:

| Offset | Size | Candidate field |
|---:|---:|---|
| 0 | 2 | `wire_version` (`0x0002`) |
| 2 | 2 | `frame_type` (`0x0001`) |
| 4 | 4 | Client's `transport_epoch` or server-epoch hint, big-endian |
| 8 | 2 | Requested `cipher_suite`, big-endian |
| 10 | 16 | Client-proposed `connection_id` |
| 26 | 768 | ML-KEM-512 ciphertext |

This layout has no explicit nonce, AEAD tag, or early-data field. The total
is 794 bytes, which is below the 1,200-byte UDP-payload starting cap. It
conflicts with the other `0x0001` candidate's 32-byte header, handshake ID,
and optional encrypted early data; implementations MUST NOT infer which
layout was sent from size or try both parsers.

The proposed transcript is
`SHAKE256(DOMAIN_TRANSCRIPT_HASH || uint16_be(cipher_suite) || connection_id || mlkem_ciphertext, 32)`,
and the proposed resume key is
`SHAKE256(DOMAIN_RESUME_KEY || mlkem_shared_secret || transcript_hash, 32)`.
The transcript should also bind the protocol version, frame type, epoch,
authenticated server-key identity/key version, and all negotiated
parameters. The suite bytes being in the transcript can detect an altered
suite only if the response is authenticated under key material derived from
the same transcript and the client verifies that response. Transcript
hashing alone does not authenticate the ML-KEM public key or server identity
and does not prevent an active attacker from substituting an unauthenticated
KEM public key.

The supplied code's comments claim `DOMAIN_TRANSCRIPT_HASH` is 37 bytes and
`DOMAIN_RESUME_KEY` is 34 bytes, but both shown ASCII labels are 35 bytes.
Its transcript buffer/copy uses 35 and is correctly sized for that label;
its resume-key buffer and copy use 34, silently omitting the final label
byte. This must be corrected and covered by known-answer vectors. The
proposed resume-key derivation also differs from the existing
`HANDSHAKE-RESUME` KDF and must be reconciled, not silently substituted.

The compact layout places the client-proposed connection ID where the
existing handshake candidate expects a client handshake ID, while the
response/ticket design expects the server to assign the connection ID.
The protocol must choose one ownership model and define uniqueness,
collision, and response binding. The proposed epoch is not included in the
transcript and the code does not validate it against an accepted server
epoch, so it must be authenticated/bound and policy-checked before use.

**Server handshake response (`0x0003`, compact-layout alternative):**

| Offset | Size | Candidate field |
|---:|---:|---|
| 0 | 2 | `wire_version` (`0x0002`) |
| 2 | 2 | `frame_type` (`0x0003`) |
| 4 | 4 | Server `transport_epoch`, big-endian |
| 8 | 8 | Server handshake-response sequence (proposed zero) |
| 16 | 16 | `connection_id` |
| 32 | 16 | `server_boot_id` |
| 48 | 112 | Opaque ticket, protected by the outer AEAD |
| 160 | N | Encrypted optional server application payload |
| 160 + N | 16 | Outer AEAD tag |

This layout has a 48-byte cleartext header, a 112-byte ticket inside the
AEAD-protected plaintext, and a 16-byte tag: 176 bytes of fixed framing and
ticket overhead. With a 1,200-byte UDP-payload cap, it leaves up to 1,024
bytes for the optional application payload. The minimum datagram is 176
bytes. The header, including the cleartext boot ID, is associated data; the
boot ID is also an input to the resumed directional-key derivation. Any
change to it therefore causes authentication failure, assuming the client
uses the expected authenticated response key.

For this KDF alternative, the response uses `HANDSHAKE_KEY` and the
single-use `HANDSHAKE_IV` directly as its XChaCha20-Poly1305 nonce. This
domain is separate from the `0x0004` traffic keys and replay window; it
does not consume an application sequence number. "Single-use" means one
unique response plaintext may be encrypted under that key/nonce. If the
server retransmits, it MUST resend the exact cached ciphertext and MUST NOT
encrypt changed plaintext under the reused key/nonce. The client may accept
the response only while its matching handshake attempt is pending, then
transition that attempt to established.

The state transition must not publish `Established` before authenticating
the response. Use an exclusive intermediate `ProcessingHandshake` state
acquired from `PendingHandshake`; on successful authentication and
validation, transition to `Established`, and on a retryable failure, return
to pending only if that same processing attempt still owns the transition.
Otherwise another thread may observe the connection as established before
authentication has completed. Duplicate responses after establishment are
stale and must not re-deliver the ticket or application data.

To ignore a retransmission after establishment, retain a digest of the
original authenticated wire datagram (including ciphertext and tag), or
compare against a bounded cached copy. Compute that digest before any
in-place decryption, but publish it only after successful authentication.
The latest parser hashes the input before decryption and caches that digest
only after authentication, so byte-identical wire retransmissions can be
recognized. It also enforces response sequence zero. The corrected
publication block copies the authenticated boot ID and ticket, sets the
payload outputs, and stores the verified datagram hash before the
release-store to `Established`, fixing the earlier ordering issue. The
release store synchronizes with an acquire operation that reads the
published phase; this does not by itself make caller-owned output buffers
safe for unsynchronized concurrent access. Their ownership/lifetime must
ensure consumers read them only after the handshake call has completed or
after an acquire observation of the established state, with no concurrent
writer.

Successful AEAD verification under a response key derived from the KEM
shared secret and transcript provides key confirmation that the responder
obtained the shared secret. It does not authenticate the server's identity
or prevent public-key substitution unless the client's ML-KEM public-key
selection is itself authenticated (for example, by a trusted pinned key or
an authenticated key-distribution mechanism). The response must bind the
same protocol version, epoch, suite, KEM ciphertext/transcript, and
connection-ID ownership model used by the initiation. This compact response
replaces, rather than combines with, the earlier 228-byte response layout;
the two layouts MUST NOT be guessed or parsed interchangeably.

**Server-to-client resumed data (`0x0004`):**

| Offset | Size | Candidate field |
|---:|---:|---|
| 0 | 2 | `wire_version` (`0x0002`) |
| 2 | 2 | `frame_type` (`0x0004`) |
| 4 | 4 | Server-to-client `transport_epoch`, big-endian |
| 8 | 8 | Server transmit `packet_seq_no`, big-endian |
| 16 | 16 | `connection_id` |
| 32 | N | Encrypted application payload |
| 32 + N | 16 | Outer AEAD tag |

This direction-specific frame omits the 112-byte ticket block because the
client already holds its ticket and `K_client_resume`. Its proposed AAD is
`[0, 32)`, minimum size is 48 bytes, and payload length is
`datagram_length - 48`. In the IETF ChaCha20-Poly1305 suite, the 12-byte
nonce is derived as `BASE_IV XOR (0x00000000 ||
uint64_be(packet_seq_no))`. The later XChaCha20-Poly1305 suite instead
derives a 24-byte base nonce and XORs the big-endian sequence into its low
eight bytes. Neither nonce is carried in the frame. Under a 1,200-byte
UDP-payload cap, the frame carries at most 1,152 bytes of application
payload. The cap remains a conservative starting point under base
IPv6/UDP-header assumptions; the actual path-MTU policy still applies. It
uses the server-to-client directional key and an independent sequence/replay
window. The client-to-server `0x0002` layout and server-to-client `0x0004`
layout MUST remain distinct; a receiver must not infer direction from an
unauthenticated identifier alone.

The proposed direction byte (`0x00` for client-to-server, `0x01` for
server-to-client) is a useful context input. The keyed BLAKE2b placeholder
is superseded by this candidate SHAKE-256 input encoding:

`SHAKE256(DOMAIN_DIR_KEYS || suite_id || K_client_resume || connection_id || server_boot_id || uint32_be(transport_epoch) || direction_flag, output_length)`

The parser proposal's suite constants are not yet shown in the wire format or
authenticated handshake transcript, and its `derive_client_rx_material`
placeholder does not include `suite_id`. The suite identifier must be
specified as a fixed-width field and included in authenticated negotiation
and both peers' derivations. With the
41-byte `DOMAIN_DIR_KEYS`, suite identifier, and 32 + 16 + 16 + 4 + 1
bytes of other inputs, the full SHAKE input length is 110 bytes plus the
suite identifier's encoded width. `server_boot_id` is a public,
restart-scoped 16-byte identifier shared by all workers for this server
replay-state domain. The handshake MUST convey it inside authenticated
server-to-client handshake data and the client MUST retain it with the
resumption state. A boot-ID change makes the old directional key
unavailable; clients must establish fresh authenticated state rather than
silently try old and new values. The suite-specific output is split into
the AEAD key and base nonce as described above. The server-to-client
key/nonce material is the client's receive material; the client-to-server
material uses the other direction value. The exact suite identifier,
output length, and known-answer vectors must be fixed before
interoperability or cross-suite key separation can be claimed.

#### Candidate server egress key cache and sequence allocation

The proposed server egress path derives the server-to-client traffic key and
base nonce once per authenticated connection/transport epoch, retains them
for packet sealing, and derives each packet nonce as the base nonce XORed
with the low eight bytes of `uint64_be(packet_seq_no)`. This is consistent
with the XChaCha `0x0004` nonce candidate above and avoids repeating the
SHAKE KDF for every datagram. The cached material MUST come from the selected
suite- and direction-bound KDF, be scoped to the connection and epoch, and
be retired/wiped when that key scope ends. It must not be accepted as
arbitrary caller-supplied key material at an untrusted Node-API boundary.

An atomic sequence allocator can assign distinct sequence values to
concurrent seal operations, and `memory_order_relaxed` is sufficient for
uniqueness when the atomic is only a counter and the connection/key state is
already safely published. That guarantee is conditional on never reusing or
wrapping the counter under the same directional key. `fetch_add` does not
provide saturation: after returning an exhausted value it continues
incrementing and eventually wraps to zero. A robust allocator must enter a
permanent exhausted state without wrap (for example with a checked CAS
loop), or otherwise prove the counter cannot approach wrap and prevent
further sends at the configured ceiling. Define whether failed calls consume
sequence numbers; gaps are safe, reuse is not. Concurrent packet completion
or network-send order may differ from allocation order, so the receiver must
support the resulting reordering.

`std::atomic<uint64_t>` is not guaranteed lock-free on every supported
platform. Lock-freedom is an implementation property, not a consequence of
using `fetch_add`; a `static_assert(std::atomic<uint64_t>::is_always_lock_free)`
can enforce a supported-target policy at compile time, but it excludes
platforms that do not meet that policy. Avoid claims of nanosecond or
sub-microsecond end-to-end latency without measurements covering the AEAD,
header handling, allocation, Node-API boundary, and target hardware.
Pre-derivation removes a per-packet KDF call but does not by itself establish
an end-to-end latency bound.

The proposed egress helper's 1,152-byte payload maximum is arithmetically
consistent with a 1,200-byte datagram cap minus the 32-byte header and
16-byte tag, subject to the same path-MTU caveat as the receive format. The
implementation must define and use the exact big-endian header writers and
must reject oversize payloads and undersize output spans before writing.
It must also define aliasing: if the input payload overlaps the output
datagram (particularly the header or tag), writing the header can corrupt
the payload before encryption. An overlap check must cover the output bytes
the operation actually writes (`required_size`), not unused capacity in the
entire output span, and must avoid unchecked address-plus-length overflow.
Either forbid overlapping spans and validate that contract at the binding
boundary, or allow only a documented exact in-place payload placement if the
AEAD implementation guarantees it; otherwise copy/handle overlap safely.
Initialize `out_written_len` on every path and define whether the output
buffer can contain partial data after a crypto or argument failure.

The proposed `fetch_add` followed by `store(MAX_VALID_SEQ_NO)` on exhaustion
is not a sound monotonic saturating allocator: concurrent exhausted callers
can race their stores against increments, and the counter is deliberately
moved backward from values above the ceiling. Although those callers should
not seal packets, this does not meet the stated strict-monotonicity invariant.
Reserve sequence values with a checked compare/exchange loop that refuses
to advance once exhausted, and test many concurrent calls at and beyond the
ceiling. A compile-time lock-free assertion is an optional supported-platform
constraint; it does not repair the allocator's exhaustion logic.

The sample's `ServerConnection` constructor accepts a raw transmit key and
base nonce from JavaScript and stores them for outbound authentication. This
is suitable only behind a trusted key-schedule boundary; exposing it to
untrusted JS lets callers choose keys/nonces and bypass negotiated suite,
direction, epoch, and transcript binding. Prefer constructing the egress
state from authenticated server session state inside the native boundary,
or explicitly restrict/document the constructor as privileged. The state
must be fully initialized before concurrent sends, remain alive throughout
all in-flight operations, and not be wiped by finalization until those
operations are complete. A synchronous `ObjectWrap` method does not itself
provide a safe async worker lifetime or concurrent-destruction guarantee.

Replacing raw transmit-key inputs with a JavaScript-supplied
`client_resume_key` is an improvement only if the resume secret is itself
permitted to cross into JavaScript. It remains cryptographic key material;
deriving `tx_key` natively does not undo exposure of the input secret to
middleware, logs, heap snapshots, or other JS code. For a strict native
key-isolation boundary, the trusted native component should validate/open
the opaque ticket using its STEK keyring, retain the recovered resume secret
in native-owned state, derive the server-to-client key using the
authenticated suite, `direction_flag = 0x01`, connection ID, boot ID, and
transport epoch, then wipe temporary material before returning. If the
middleware is intentionally trusted with the resume key, document that
threat-model choice and still enforce the complete authenticated KDF context
inside native code. Egress must not use a client-to-server direction key.

#### Middleware, UDP-buffer pool, and connection-lifecycle proposal

The accompanying JavaScript middleware blueprint is architectural only and
does not implement a zero-copy `dgram` receive path. Node's `dgram` message
event supplies a Buffer containing each received datagram; creating
`UdpBufferPool.acquire()` views does not cause the socket to receive into
those views, and the sample never copies or otherwise directs the received
bytes into the pool. Replacing the slab when it fills also does not recycle
slots or track outstanding views. A real reusable receive pool requires a
socket/native API that supports caller-provided receive storage, or an
explicit copy from the event Buffer (which is not zero-copy). `Buffer.allocUnsafe`
is safe only when every byte that can be observed is overwritten before use;
track valid datagram length and do not expose stale slab contents.

The cleartext payload returned by in-place decryption is a `subarray` view
that aliases the received datagram's backing store. This avoids an additional
payload copy within the process, but is not end-to-end zero-copy from the
network or necessarily through a DLP engine. If the DLP operation is
asynchronous, the owner must retain the backing Buffer and prevent reuse or
wiping until inspection completes; if native ingress or another consumer
mutates it, the DLP view observes that mutation. Do not return a pooled slot
to circulation while any such view remains in use.

The proposed routing flow is inconsistent with the candidate frame
directions and ticket placement. `0x0003` is the server-to-client handshake
response, not the incoming client handshake request; its compact candidate
places the opaque ticket inside the outer AEAD-protected plaintext, so a
router cannot read that ticket's cleartext key ID before authenticating and
opening the response. A client must not hold or select server STEK keys at
all. For server-side ticket routing, the relevant input is a client
resumption request that carries the opaque ticket (candidate `0x0002`), and
the exact ticket envelope must put a bounded selector where the server can
read it; the current provisional ticket format does not define the later
four-byte key-ID envelope as canonical. Do not route based on `0x0003` or
treat a cleartext selector as authenticated before ticket AEAD verification.

`KeyRouter` stores master-key Buffers in a JavaScript `Map`, exposing them
to JS heap inspection and all code with access to the map. This may be an
intentional trusted-server deployment choice, but it does not satisfy a
native key-isolation design. Key lookup should be bounded and performed in
the trusted ticket-opening component, with active/retired key lifetime and
unknown-ID behavior defined. The shown `ConnectionManager.upsert` likewise
accepts raw `txKey`/`txBaseIv`, contrary to the proposed native
key-derivation boundary. Dropping a Map reference does not deterministically
run a V8 finalizer or immediately wipe native state; GC/finalization is
nondeterministic, and other references or in-flight operations may keep an
object alive. TTL eviction is a reachability policy, not a secure-erasure
guarantee. Explicit close/retire semantics and safe draining of in-flight
work are needed, with best-effort destruction as a fallback.

The sample `SentinelTransport` also calls
`processApplicationDatagram(datagramBuf)` with one argument, while the
illustrative client Node-API signature requires the datagram, resume key, and
server boot ID. Those client-side inputs must not be copied blindly into a
server ingress API; define separate server/client interfaces and keep secrets
native where required. The sample reads a header after checking only a
32-byte minimum, omits version, supported frame-type, and maximum-datagram
checks, silently drops malformed input without a specified error policy, and
calls an undefined `_handleHandshakeRequest`. Its `0x0004` dispatch is
server-to-client traffic and is not the normal client-to-server resumed
ingress path. Implement routing only after each endpoint's frame direction,
minimum/maximum length, key context, and native method contract are fixed.

Finally, the manager needs an explicit shutdown method that clears its sweep
timer. Replacing an existing connection entry should retire the prior
connection deliberately rather than assuming it becomes unreachable.
Concurrent/asynchronous operations need independent state ownership so
eviction cannot race key use or destruction.

#### Native libuv receive-slab proposal

The later `ZeroCopyUdpServer` sketch can, in principle, provide libuv receive
buffers backed by a V8 Buffer's memory, but it does not yet provide safe
zero-copy packet delivery. `Start` retains only `slab.Data()` and the size;
it must also retain a strong Node-API reference to the Buffer until receive
has stopped, the UDP handle's close callback has completed, and no queued
callback can use the slab. The JavaScript example happens to keep `this.slab`
reachable while active, but the native API must not rely on every caller
doing so. Likewise, `handle_.data = this` is unsafe if the wrapped object can
be finalized while the libuv handle or callbacks remain active. Keep native
state alive through asynchronous close and in-flight work, and make repeated
start/stop/close and finalization transitions explicit.

The rotating slab cursor is not a ring-buffer ownership protocol. It wraps to
offset zero without knowing whether JavaScript has consumed an earlier
packet, so a later receive can overwrite bytes before the queued
`ThreadSafeFunction` callback reads them or while a `subarray`/DLP consumer
still holds a view. Integer-only callbacks do not snapshot payload bytes.
Use per-slot ownership/backpressure with release after consumer completion,
or copy into separately owned storage; do not reuse a slot while outstanding
views exist. The sketch also allocates `new PacketData` for each packet and
queues an unbounded TSFN (`maxQueueSize = 0`), so it still has per-packet
native allocation and can accumulate unbounded queued work. Define a bounded
queue and an explicit drop/backpressure policy; free packet metadata on every
queue failure and shutdown path.

Before starting receive, validate that the slab is non-null and at least one
maximum receive slot, check all size arithmetic, and ensure the allocated
`uv_buf_t` range stays within the retained backing store. Handle
`UV_UDP_PARTIAL` as a truncated datagram and reject it; distinguish
`nread < 0` errors from the valid zero-length UDP datagram case rather than
silently discarding both. Define behavior for a null source address and pass
needed peer metadata to the callback. Ensure each delivered offset and length
is within the slab and within the actual datagram, not just the allocation
capacity. The current cursor can silently reuse space and does not reserve
space for outstanding datagrams.

`uv_close` is asynchronous, so calling it is not immediate deterministic
cleanup. Supply a close callback to release the slab reference, TSFN, and
native state only after libuv is done; coordinate `uv_udp_recv_stop`, queued
TSFN callbacks, and outstanding packet views. Releasing the TSFN before
draining or disposing queued `PacketData` needs an explicit cleanup path.
`Stop` and `Close` must check libuv statuses and be safe when called more
than once or after a partial initialization failure. Check returns from
`napi_get_uv_event_loop`, `uv_udp_init`, `uv_ip4_addr`, bind, receive-start,
and TSFN creation. The current code ignores several of these results, accepts
an unchecked/truncated port conversion, supports IPv4 only, and reports
errors by throwing without a complete rollback path. Direct libuv use also
couples the addon to Node's bundled libuv API/version and must be included in
the supported-platform/Node-version contract; it is not covered by Node-API
ABI stability alone.

This design would eliminate a copy from libuv's receive buffer into a
per-message JavaScript payload Buffer only if the slot lifetime protocol is
correct. It does not eliminate the small per-message JS view/callback
overhead, native metadata allocation as written, kernel-to-user copy, or
copies an application/DLP component may perform. Describe it as
application-level receive-buffer reuse rather than claiming no V8
allocations or zero-copy from the network. The middleware must keep each view
valid until its consumer finishes and must not decrypt/wipe or recycle the
same slot concurrently.

#### Proposed UDP-to-DLP integration test

The proposed `test/test_integration_v2.mjs` is not present or runnable in the
current repository: there is no `lib/transport/ZeroCopyUdp.js`, v2 addon
target, `ServerConnection`, DLP wrapper, or native sealing helper. Its
description also overstates its evidence. The test itself uses a
`ThreadSafeFunction` callback and creates a JavaScript `subarray` view, so it
does not prove there is no V8 allocation or no JS/native boundary crossing.
It can at most verify that a delivered view aliases the slab, if the native
receive wrapper's ownership protocol is correct.

The packet is labeled as a client transmission but uses frame type `0x0004`
and `sealServerDatagramV2`, both defined as server-to-client in the candidate
protocol. A server receiving client resumed traffic must use the distinct
client-to-server `0x0002` format, key derivation, and ingress implementation.
The header comment calling `0x0004` a "client resumed" type does not change
the wire direction. In addition, the test constructs `ServerConnection` with
raw client/server traffic keys and a DLP object, bypassing the proposed
trusted ticket-open and native key-schedule path. A valid integration fixture
must use matching sender/receiver direction-specific key material and an
explicit test-only trusted state factory, without weakening the production
constructor.

The test uses `bootId` only in the sealing helper, but the shown server
connection constructor and `processApplicationDatagram` call do not provide
it. Unless the server-side derivation obtains the same authenticated
boot-scoped context internally, the helper's ciphertext and receiver's key
will not correspond. The test must also establish that replay state accepts
sequence zero, that the configured DLP engine is actually attached and
immutable, and that replay commit precedes publication of the sanitized
payload.

Finally, the test needs deterministic startup/readiness and teardown. It
binds and immediately sends without awaiting an explicit listening/readiness
signal, has no timeout for a missing datagram/callback, and throws from the
UDP send callback rather than rejecting the test promise. Its `after` hook
does not itself establish that asynchronous `uv_close` has completed before
the test process exits or the slab is released. Cleanup should be awaitable
and run in a `finally` path, including send, callback, assertion, and startup
failures; native close must retain the slab until its close callback and
queued callbacks are finished.

#### Native in-place DLP redaction proposal

The proposed native DLP stage can avoid handing unsanitized plaintext to
JavaScript only if it runs inside the trusted ingress boundary and no other
callback, log, error path, or buffer view exposes the plaintext first. It
does not eliminate the V8 boundary crossing for the eventual sanitized
result; a Buffer/view or copy still has to be delivered to JS if JS or a JS
DLP service consumes it. It may avoid a TSFN hop for inspection when invoked
synchronously on the libuv event-loop thread, but synchronous scanning also
occupies that thread and can delay unrelated I/O. If crypto or scanning is
moved to workers, the slab lifetime and bounded-queue rules still apply.
Claims that plaintext is "hot in L1/L2" or that the work is sub-microsecond
require measurement on target hardware and cannot be inferred from code
placement.

The sample matcher needs input and lifecycle constraints. `add_exact_match_rule`
accepts an empty token, after which `rule.pattern[0]` is an out-of-bounds
read; reject empty patterns and set explicit maximum rule count and pattern
length. `std::vector` growth and string conversion can throw during
configuration, so those errors must be surfaced before accepting traffic.
After startup, publish an immutable ruleset or synchronize updates against
concurrent scans; `rules_` cannot be mutated while `redact_in_place` iterates.
Document byte encoding and matching semantics (the implementation is
case-sensitive byte matching, not Unicode-aware token detection), overlapping
matches, and whether multiple rules can interact after earlier matches have
been overwritten. A fixed `'*'` replacement preserves length but does not
preserve text semantics and is not sufficient for every structured protocol
or secret format.

The current implementation is a straightforward per-rule `memchr` plus
`memcmp` scan, with worst-case work proportional to rules, payload length,
and pattern length; including `<immintrin.h>` does not vectorize it. Define
performance limits and benchmark adversarial inputs before claiming
high-throughput scanning. Rule values are themselves sensitive configuration
and should not be exposed in logs, crash reports, or unnecessary JS/native
copies. If the sanitizer cannot complete or its ruleset is invalid, the
transport must fail closed: do not deliver unredacted plaintext.

The ingress sketch omits the surrounding state and replay-commit ordering.
The receive path must authenticate first, then atomically commit the replay
sequence before making any plaintext externally observable. Redaction should
occur after successful authentication and replay commit and before returning
or dispatching the payload. On replay rejection or DLP failure, wipe the
decrypted bytes and return no payload offsets. If redaction occurs before
replay commit, duplicate packets can trigger repeated DLP work and the code
must still guarantee that no rejected plaintext escapes. Initialize output
offset/length to zero on entry, keep them zero on every error, and validate
the packet size/tag/pointer ranges before in-place AEAD operations.

`DlpRedactionEngine` configuration and `ServerConnection` processing should
share a stable immutable engine snapshot or an explicitly synchronized
owner; a mutable `shared_ptr` by itself does not make the pointed-to rules
thread-safe. The addon must also decide whether redaction state is per
environment, per server, or per connection, and ensure it remains alive
through in-flight ingress. The full pipeline (authenticated open, replay
commit, redact, then publish sanitized bytes) needs native tests for empty and
overlapping rules, multiple-rule interactions, binary/NUL-containing
payloads, malformed frames, duplicate sequences, DLP failure, output
zeroization, and proof that no unsanitized plaintext is returned on any
failure path.

#### Injecting a DLP engine into server connections

Passing a DLP wrapper object to a server-connection constructor and retaining
its `std::shared_ptr` can keep the C++ engine allocation alive after the JS
wrapper becomes unreachable. `ObjectWrap::Unwrap` is not, by itself, proof
that an arbitrary JS object is an instance of `DlpEngineWrapper`; validate
the instance using the retained constructor's `InstanceOf` check or a
Node-API type tag before unwrapping, and handle unwrap failure as an explicit
type error. A generic `IsObject()` test is insufficient. The optional
argument should also have a clear contract for `undefined`/`null`, invalid
objects, and failed wrapper initialization.

The shared pointer only manages object lifetime; it does not make
`DlpRedactionEngine::rules_` safe for concurrent mutation and scanning. The
proposed JavaScript setup adds rules before connections, which is a useful
configuration order, but the API must enforce or document that rules are
frozen before publication. Otherwise use immutable snapshots or synchronization
around rule updates and scans. A shared DLP engine must remain alive through
all in-flight operations, and a connection must not hold a raw engine pointer
after releasing the owning shared pointer.

There is a Node-API environment-state collision in the combined sketches:
both `DlpEngineWrapper::Init` and `ServerConnectionV2::Init` call
`env.SetInstanceData<Napi::FunctionReference>(...)`. Node-API provides one
instance-data slot per environment, not one per wrapper class; the later
registration replaces the prior slot/finalizer association. Store all
constructors in one environment-owned aggregate with one finalizer, or use
another per-type/per-environment lifetime mechanism. The configured
node-addon-api default finalizer only deletes the pointer currently
registered in that slot.

The proposed server constructor still accepts raw `rxKey` and `txKey` Buffers
from JavaScript, and calls the former "rx" while using server-side ingress.
That conflicts with the native key-isolation model and leaves direction
semantics unclear. Prefer a trusted native session/ticket-open path that
derives and stores the correctly direction-bound keys, then attaches the
validated DLP engine. If JavaScript is explicitly inside the trusted
cryptographic boundary, document the secret exposure and validate exact
lengths, epoch/suite binding, and direction before constructing the native
state. The sample `std::make_shared`/`std::make_unique` allocations can
throw; surface allocation failures as JS errors and do not let exceptions
escape through native callbacks or `noexcept` ingress code.

#### Dynamic DLP manager and guardrail/admin integration proposal

The proposed `DynamicDlpManager` is not currently present in this repository,
and its import expects a `lattice_native_v2` addon that is not built or
exported here. Treat the code as a design sketch, not an integration that can
be run or attached to the existing `ConnectionManager`.

The manager claims to own a singleton but its constructor creates a new
native engine for every instance; enforce one shared manager per process (or
explicitly define independent policy scopes) and inject the exact same
underlying engine into every relevant connection. Verify the native wrapper
type and ownership at the addon boundary. Adding a rule must not mutate
storage a UDP reader is currently scanning. Immutable snapshot publication
can give per-read consistency, but an update is not retroactive: an in-flight
datagram may finish against the old snapshot. Define the update's
linearization point and whether ingress must drain before an update is
reported as globally effective. The proposed `std::atomic<shared_ptr>` does
not itself establish a lock-free/nonblocking reader guarantee.

`banToken()` performs a full ruleset clone synchronously on the JavaScript
event loop, so its work and allocation cost grow with the number and total
size of rules. It is not guaranteed to complete in under a millisecond and
can stall both HTTP handling and JS-owned UDP work. Concurrent native or
multi-isolate writers also need serialization or a compare-exchange update
loop to avoid losing rules. Define maximum token bytes, rule count, and total
ruleset size; reject invalid input and surface native allocation/configuration
errors. The JavaScript character-length checks do not necessarily equal the
UTF-8 byte length scanned by native code.

`activeRuleCount` is incremented for every call, even if a duplicate rule is
added or the native operation fails, and does not prove it equals the
published native set. Make add/update return an explicit result and count
unique committed rules from the authoritative ruleset. `EventEmitter.emit()`
invokes listeners synchronously; a listener exception can make `banToken()`
appear to fail after the native policy has already changed. Isolate
observability failures from the policy commit, and keep logs from exposing
the secret: the proposed first-three/last-three mask reveals the entire token
for short values and leaks portions of longer ones. Prefer a constant mask or
a non-reversible keyed identifier, and never persist raw values in ordinary
logs.

The admin route is not secured as shown: the JWT/mTLS `preHandler` is only a
comment, not configured behavior. Do not register this route in a reachable
service until authentication, authorization, TLS/trusted-proxy assumptions,
request-size limits, rate limits, and audit policy are enforced. The body
contains the secret token, so avoid logging it and require protected transport.
Also bound update frequency and accepted rule sizes to prevent an authorized
or compromised feed from forcing repeated O(n) clones and memory growth.

The guardrail path sends `cleartextPayload` to an AI provider; this is a
sensitive-data egress boundary, not merely an asynchronous implementation
detail. Specify provider trust, data minimization/redaction, retention, and
user/tenant policy before transmitting decrypted content. Treat the model
response and `extractedSecrets` as untrusted input: validate the response
shape, token byte lengths, count, source, and severity, deduplicate results,
and require an explicit policy before any finding becomes a global ban.
Otherwise prompt manipulation or a malformed provider response can flood the
rule set, cause event-loop stalls, or redact unrelated traffic. Bound
concurrent inspections and queue size; asynchronous analysis must not retain
or reuse a mutable pooled datagram after its owner releases the buffer.

#### Distributed DLP rule synchronization proposal

The proposed Redis-backed manager and bootstrap integration are not present
in this repository. Treat them as a design sketch, not a verified fleet-wide
consistency mechanism. Redis Pub/Sub is ephemeral, at-most-once delivery:
disconnected subscribers miss messages, and `PUBLISH` does not confirm that
every intended proxy applied the update. The persistent set can help a later
instance recover state, but it does not repair rules missed by already
running instances without periodic reconciliation or a durable change log.

The startup order has a race. Reading `SMEMBERS` and then subscribing can
miss a rule committed between those operations; subscribing first and then
loading the set can instead apply duplicate or out-of-order state. Make rule
updates idempotent and versioned, and use a durable ordered log/snapshot
protocol (for example, a Redis Stream with a snapshot cursor) or another
atomic bootstrap-and-replay design. Define the point at which an instance is
ready to accept UDP traffic, how it detects gaps/reconnects, and how it
reconciles from the authoritative version.

The local-first mutation order intentionally allows divergence. `banTokens`
adds values to `activeRules` and applies them locally before `SADD` and
`PUBLISH`; on Redis failure it only logs and still returns success. Other
instances and future replicas can therefore remain unprotected, while the
caller receives no indication that fleet synchronization failed. Conversely,
the in-memory Set is mutated before `setRules`; if native conversion or
publication throws, the Set can claim rules are active when the native
snapshot is not. Define whether local protection or fleet-wide durability is
the success criterion, stage and commit local state only after native
publication succeeds, and expose partial outcomes explicitly. Use retryable
durable delivery/outbox semantics rather than treating a Pub/Sub publish as a
fleet-wide commit.

The resilience revision still permits unsafe startup. `initialize()` treats
a two-second timeout or Redis failure as success and allows the UDP listener
to bind without bootstrapping historical rules or subscribing. That can make
a newly scaled replica serve traffic with a stale/empty policy. Choose and
enforce an explicit readiness policy: fail closed until a consistent policy
version is loaded, or expose a clearly degraded mode that cannot claim
fleet-wide protection. `Promise.race()` does not cancel `_bootstrapFromRedis`;
the timed-out operation may later mutate the engine or subscribe after the
proxy has already started. Add cancellation/generation checks and clean up
the timeout and pending Redis work.

`isRedisHealthy` is not a circuit breaker with reliable fleet-state semantics.
It is set true on the publisher's `ready` event, before successful bootstrap,
subscriber readiness, or rule reconciliation; only publisher `close` and
caught publish-path errors set it false. Subscriber disconnects, failed
subscriptions, stale state, and Redis command health are not represented.
Track publisher and subscriber states separately, and define health in terms
of an observed authoritative version and successful subscription/replay, not
just TCP readiness. `enableOfflineQueue: false` disables one queueing
behavior, but does not mean every in-flight Redis command rejects instantly;
timeouts, retries, reconnect behavior, and pending-request limits must be
configured and measured for the chosen ioredis version.

The callback catches malformed-message and local-apply failures and then
discards them. That silently loses the broadcast while the replica may
continue serving. Validate a versioned message, record failed application,
and reconcile/retry before reporting the replica ready. Also, the initialization
code subscribes only after loading the set, retaining the bootstrap race;
timeouts do not cure that ordering problem.

The retry strategy reconnects with delays, but the application has no
durable retry/outbox for failed `SADD` or `PUBLISH`. It marks Redis unhealthy
and skips future writes until a `ready` event, at which point it simply marks
healthy again; locally accepted rules from the outage are never replayed to
Redis. If `SADD` succeeds and `PUBLISH` fails, persistence and live fan-out
diverge. Track pending versions durably and reconcile on reconnect, with
idempotent writes and explicit partial-success results. A boolean circuit
flag can shed optional Redis work, but cannot provide durability, consistency,
or proof that all replicas have applied a policy.

The native update is not guaranteed "never blocks, never fails": each call
copies the complete active set into an array, converts/allocates strings and
native rules, publishes a snapshot, and may reclaim an old snapshot. Those
operations are synchronous on the JS callback and can throw or stall. The
manager also mutates `activeRules` before native publication, so failure can
leave its Set ahead of the actual native rules. Stage validated state, handle
native errors, and only report local activation after successful publication.
Bound batches, rules, and pending outage updates.

Finally, suppressing Redis error logs during an outage can hide a prolonged
degraded state. Emit rate-limited structured health transitions and metrics
(last applied version, last successful durable write, reconnect count, queue
depth, and degraded duration), without logging raw tokens or Redis payloads.
Ensure the `Promise.race()` timeout, Redis clients, subscribers, and any
reconnect handlers are closed on shutdown.

The claimed `sub-millisecond` delivery is not guaranteed by Redis Pub/Sub,
network scheduling, Node's event loop, or native ruleset construction. Every
replica rebuilds and publishes a complete native ruleset for each batch,
which is O(total rule bytes), and the code also copies `activeRules` into a
new array. The unbounded `SMEMBERS` bootstrap materializes the entire set in
one response and in JS memory; as the set grows this increases latency and
memory pressure and can block Redis while serving a large command. Set
explicit limits for rule count, token bytes, total bytes, message size, and
batch size; paginate or use versioned snapshots, and measure update-to-active
latency at each replica.

Redis persistence makes the secret tokens durable outside the native engine.
The set and Pub/Sub JSON payload contain raw tokens, so define Redis TLS,
authentication/ACLs, encryption-at-rest and backup policy, retention/deletion,
tenant separation, and operator access before deployment. Avoid including
payloads or raw Redis messages in errors and logs. A Redis Set stores distinct
exact strings but has no inherent ordering or update metadata; it cannot by
itself represent source, severity, version, expiry, revocation, or policy
provenance. Model those explicitly in a bounded durable schema, including
rule removal/expiry and behavior for stale or conflicting updates.

The subscriber callback catches JSON and application errors, but reliability
also requires Redis client `error`/reconnect handling, payload schema and size
validation, duplicate/version checks, and backpressure. Do not silently drop
updates when local application fails; record the version as unapplied and
retry or force reconciliation. Avoid unbounded async work if messages arrive
faster than native rulesets can be rebuilt. The `ioredis` dependency is not
declared in this repository, and the suggested JS/native paths and v2 addon
are absent.

The startup snippet correctly intends to delay UDP binding until bootstrap,
but it should also await successful subscription and a consistent snapshot,
and must close Redis clients and native/socket resources on startup failure
and shutdown. `process.exit(1)` in the catch can bypass cleanup; set a failure
status and use a `finally`/shutdown path before exiting. Keep readiness false
until the versioned state is complete, and define the safe behavior if Redis
is unavailable (fail closed, serve with a known stale version, or another
explicitly chosen policy).

#### Redis diagnostic and Kubernetes probe proposal

The proposed diagnostic code is not present in this repository; the addon
does not export `evaluateNodeHealth`, and there is no `diagnostic_routes.js`
or deployment manifest. A Redis client reporting `status === 'ready'` only
describes that connection. It does not show that startup bootstrap completed,
the subscriber is caught up, the native ruleset matches the authoritative
version, or pending updates have been reconciled. The probe's
`circuitBreaker: closed` label therefore overstates health when both sockets
are ready but policy state is stale. Report connection state separately from
last-applied version, bootstrap completion, and synchronization lag.

The `/ready` handler currently treats Redis loss as degraded-but-ready and
returns HTTP 200. That is safe only if the service's explicitly chosen
degraded-mode policy allows a replica with potentially stale DLP rules to
receive traffic. It conflicts with fail-closed startup or fleet-consistency
requirements. Gate readiness on native engine initialization and the selected
policy version; make any degraded acceptance mode explicit and observable.
Kubernetes readiness is per pod and may remove it from Service endpoints, but
does not itself establish that a UDP load balancer or external GKE health
check honors the intended routing semantics; validate the actual UDP Service
and health-check path.

`evaluateNodeHealth()` cannot safely prove absence of memory corruption or
deadlocks by returning a struct from a synchronous call. If native code is
deadlocked, the handler itself may block until the HTTP probe times out; if
native memory is corrupted, invoking more native code may be unsafe. Keep
liveness checks minimal and process-oriented, and expose only bounded,
nonblocking native health snapshots maintained by the data plane. Do not
label an exception as a detected deadlock: an exception indicates a failed
check, while a stuck call is observed as a timeout. The C Node-API addon must
translate native errors explicitly; C++ exceptions must not escape through
the ABI.

The `/health` endpoint correctly avoids making Redis availability a liveness
condition, which prevents dependency outages from needlessly restarting
otherwise functioning pods. However, the proposed handler logs
`err.message` and returns it to callers, potentially exposing implementation
details. Return a stable generic error/status and keep sanitized diagnostics
in protected logs. Avoid running expensive checks on every probe at high
frequency; probe behavior must remain bounded and must not contend with or
stall ingress.

The shown GKE probes use HTTP GETs but do not specify the HTTP diagnostic
server's container port/name or its binding, and the earlier deployment only
declares a UDP container port. Kubernetes probe `httpGet` needs a reachable
HTTP listener in the pod. Configure and expose the diagnostic port separately
from the UDP data port, bind it to the intended interface, and restrict
external access. A one-second timeout is a probe budget, not evidence that a
native health call completes in microseconds. Tune startup/readiness/liveness
thresholds from measured startup and failure-recovery behavior; a readiness
failure threshold of one can flap traffic during transient pauses.

#### AVX-512 DLP scanner candidate

The proposed AVX-512 scanner compares 64 bytes per vector iteration to find
first-byte candidates, then verifies each candidate with scalar `memcmp`.
This is not a guarantee of 64 bytes per clock cycle: instruction throughput,
candidate density, rule count, cache behavior, scalar verification, and
redaction stores determine actual performance. `_tzcnt_u64` and `_blsr_u64`
also require BMI1, which is a separate CPU feature from AVX-512F/BW; build
flags and runtime feature checks must cover every emitted instruction.
Compiling the whole addon with AVX-512 flags can cause illegal-instruction
faults on CPUs without the required features. Use runtime dispatch to a
scalar/portable implementation (or explicitly restrict supported hardware
and fail safely before invoking the optimized path). The proposed
`binding.gyp` flags do not provide that dispatch, and compiler/OS support
must be verified for each toolchain rather than assumed, especially for
MSVC and macOS targets.

The vector loop has a bounds bug for payloads shorter than 64 bytes:
`raw_data + len - 64` forms a pointer before the beginning of the array, which
is undefined behavior even if the loop condition later prevents a load.
Enter the vector path only when `len >= 64`, and prefer size-based offsets
with checks such as `len - offset >= 64` to avoid invalid pointer arithmetic.
All vector loads must remain within the payload, and candidate offsets must
be less than `len - pat_len + 1` before scalar verification. Add tests around
lengths 0, 1, 63, 64, 65 and pattern lengths 1, 63, 64, and longer than the
payload, including matches at vector/tail boundaries.

The AVX loop tests all first-byte candidates from a chunk against the
original mask, even after earlier matches overwrite bytes. Therefore match
selection and overlap behavior can differ from the scalar fallback, which
advances by the matched pattern length. Define whether matches are
non-overlapping, leftmost-first, or all original-input matches, and make the
vector and scalar paths implement the same semantics, including interactions
between rules after mutation. `_mm512_set1_epi8` should also receive an
explicitly defined conversion from the token's unsigned byte to the intrinsic
argument; DLP matching is byte-oriented and must not depend on signed-char
interpretation.

The proposed `hardware_check.hpp` is not a sufficient AVX-512 runtime check.
CPUID feature bits alone do not establish that the operating system saves and
restores the extended register state. Before using AVX-512, check the maximum
basic CPUID leaf, CPUID.1:ECX.OSXSAVE and AVX, then (only when OSXSAVE is set)
read XCR0 and require the XMM, YMM, opmask, ZMM-high-256, and high-16-ZMM
state bits (`0xE6`); also require CPUID.7.0:EBX.AVX512F and AVX512BW. Check
BMI1 separately if the implementation uses `_tzcnt_u64` or `_blsr_u64`.
Guard `XGETBV` so it is never executed on an unsupported OS/CPU. The current
wrapper also treats every GCC/Clang target as x86 when including/using
`cpuid.h`; guard on the target architecture and provide a defined unsupported
result for non-x86 builds.

The `CMPXCHG16B` CPUID bit only says the processor supports that instruction.
It does not prove that `std::atomic<ReplayWindow>` is always lock-free or that
the selected compiler/library emits the instruction. Combine the runtime
feature check with compile-time and runtime atomic lock-freedom checks for
the exact build; keep a correct fallback or fail initialization with a
specific diagnostic when lock-freedom is a hard platform requirement.

The revised `supports_avx512_full()` adds the important XCR0 state check, but
still needs several guards before it is safe to use:

- Require the maximum basic CPUID leaf to be at least 7 before querying
  leaf 7, and require CPUID.1:ECX.AVX as well as OSXSAVE before executing
  XGETBV. The required XCR0 mask `0xE6` is appropriate for AVX-512 state;
  XGETBV must be reachable only after the OSXSAVE check.
- Compile and execute this detector only on supported x86 targets. As
  written, the GCC/Clang branch unconditionally includes `<cpuid.h>` and
  calls `_xgetbv`, which is not portable to non-x86 builds; the fallback
  branch does not help when those compiler branches are selected on ARM.
  Verify the compiler intrinsic's target requirements without enabling
  AVX-512 globally, or use a baseline-safe implementation.
- Keep each optimized kernel's required feature set exact. BMI1 is needed
  only if the selected implementation emits BMI1 instructions; AVX512F/BW
  and OS state are independently required. The OS-aware detector must be
  the one actually used by dispatch, not just present in a header.

The function-pointer design is directionally sound, but the code shown is
not yet a complete safe dispatcher. The AVX-512 function must be prevented
from inlining into baseline code, and its definition must be placed so that
the target attribute is honored for every translation unit (the non-`inline`
function definitions in a header also create multiple-definition risks).
For MSVC, compile a dedicated AVX-512 source file with the toolset-supported
flag and keep the dispatcher and feature detector in baseline-safe files.
Initialize the function pointer only after successful detection, and retain
a scalar implementation for unsupported CPUs. Do not assume AVX2 or SSE4 is
a universal baseline: pick and document the minimum deployment ISA, or compile
the fallback for the platform ABI baseline. The example checks hardware in
each engine constructor, not once per module as its prose claims; a cached
process-wide capability result is optional, but must be initialized safely
and must not run AVX-512 code during static initialization.

The scanner rules are mutable `std::vector` state. Adding a rule while a
redaction call reads the vector is a data race; finish configuration before
publishing the engine to ingress or provide synchronization/immutable rule
snapshots. `add_exact_match_rule()` silently ignores an empty token and can
throw during vector allocation, while the proposed redaction call is
`noexcept`; define explicit configuration errors and ensure exceptions cannot
escape the native boundary or terminate ingress. Include the required
`<string_view>` and other direct dependencies rather than relying on
transitive includes.

The proposed `std::atomic<std::shared_ptr<const RuleSet>>` snapshot is a
reasonable way to make published rules immutable and safely keep an old
snapshot alive while a scan uses it, but it does not guarantee lock-free or
nonblocking readers. C++20 atomic shared-pointer operations are atomic, yet
`is_lock_free()` may be false and implementations may use internal locks;
the reference-count updates also contend on shared control-block state.
Check the actual implementation if lock-freedom is a requirement, and do not
describe shared-pointer pinning as "entirely lock-free." Even where the atomic
pointer operation is lock-free, the last reader can run vector/control-block
destruction and deallocation on the ingress thread after a writer swaps the
snapshot, causing latency spikes.

The writer's load-copy-store sequence is not safe for concurrent writers:
two rule additions can load the same snapshot and the later store can discard
the earlier addition. Serialize configuration updates or use a
compare-exchange loop that rebuilds from the latest observed snapshot after
failure. Define whether configuration is permitted after ingress begins.
Allocation/copy failures also need an explicit API error path; they must not
silently lose a rule or escape an addon callback.

If strict nonblocking readers are required, use a reclamation design whose
progress and lifetime guarantees are specified (for example, epoch-based
reclamation or carefully managed hazard pointers), or accept the shared_ptr
cost and state the actual guarantee as atomic snapshot consistency rather
than lock-free RCU. Such alternatives require tests for concurrent rule
publication, reader lifetime, writer races, and reclamation under sustained
traffic; a successful compile alone does not establish those properties.

An initialization-time check cannot protect code compiled globally with
AVX-512 flags: the compiler may emit those instructions in ordinary functions,
initializers, or the feature-check path itself before dispatch. Compile the
module baseline-safe and isolate ISA-specific functions (with target-specific
attributes/options or separate translation units), dispatch only after the
complete CPU-and-OS check, and retain a scalar implementation. Rejecting the
entire addon because AVX-512 is unavailable is unnecessary when the optimized
DLP path has a valid fallback; if the product instead requires AVX-512, make
that an explicit deployment constraint.

#### Proposed GKE/GCE ISA-pinned deployment

The proposed infrastructure files are not present in this repository, and
the `apiVersion: container.gcp.google.com/v1`, `kind: NodePool` document is
not a standard Kubernetes API object to apply with `kubectl`. GKE node pools
are managed through the GKE API or infrastructure tooling such as
Terraform/gcloud; configure machine type, minimum CPU platform, labels, and
taints through that supported resource/API, then verify the resulting node
metadata. A deployment manifest's `nodeSelector` only works if the selected
labels are actually applied to those nodes, and tolerating a taint alone does
not prove hardware capability.

An Intel Cascade Lake minimum platform is a plausible x86 deployment
constraint for AVX-512F/BW and CX16, but a machine-family name or node label
is not a substitute for checking the features exposed to the running guest.
Confirm the selected machine type and minimum platform are compatible and
available in the chosen zone, and validate CPUID plus OS-enabled XCR0 state
inside the VM/container at startup. Keep the native runtime dispatch and
unsupported-CPU behavior even with node placement constraints; scheduling
configuration can drift, be misapplied, or change during migrations.
Deployment may require a compatible GKE version, node image, quota, and
regional capacity; fail deployment clearly if the requested platform cannot
be provisioned rather than silently relaxing the constraint.

The proposed Node.js GC settings do not manage native RCU snapshot lifetime.
`--max-old-space-size` limits V8's old-generation heap; it does not force
collection of native `std::vector`/`shared_ptr` allocations or reclaim a
snapshot still held by a reader. Native memory should be bounded and measured
explicitly, with deliberate snapshot retirement/reclamation. `--predictable`
does not make the V8 or libuv scheduler constant-time and is not an ingress
throughput optimization; benchmark its impact before using it.

The workload manifest also declares a UDP container port but shows no
Kubernetes `Service` or other exposure/routing configuration. A container
port declaration by itself does not expose a UDP service. Define the UDP
Service/load-balancer and health-check behavior, and ensure the actual
service preserves the datagram transport and source-address requirements.
The deployment uses a 1 GiB memory request and 2 GiB limit while continuously
allocating replacement rulesets; size these from bounded rule limits,
snapshot-retirement peaks, native memory, and measured traffic rather than
assuming Node heap settings cover the total process.

The proposed addon hook uses node-addon-api (`Napi::*`), but this repository's
`src/addon.cpp` uses the C Node-API (`napi_*`) and the suggested
`hardware_check.hpp` and `lib/index.js` do not exist here. Do not copy the
hook as-is; adapt the error path to the project's binding API and preserve a
stable error code rather than requiring JavaScript to parse a message string.
Calling `process.exit(128)` inside middleware is also an application policy,
not a portable library fallback: it bypasses normal shutdown/cleanup and may
cause an orchestrator restart loop. Surface an explicit initialization error
and let the executable's startup policy decide whether to terminate.

The proposed `test/test_dlp_avx512.mjs` has useful functional cases for the
scalar path, 64-byte chunks, cross-chunk matches, empty input, no rules, and
multiple rules, but it is not currently runnable here: the repository has no
`lattice_native_v2` target or `DlpRedactionEngine` export. The wrapper must
validate Buffer arguments and expose a synchronous `redactInPlace` method
only after native DLP is implemented; this test alone cannot validate a
network-ingress sanitizer or prove that unsanitized plaintext never escapes.

The proposed `Napi::ObjectWrap::RedactInPlace` method can synchronously create
a span over a validated Node.js Buffer's contiguous backing store and mutate
those bytes in place without copying the payload. This is a direct native
Buffer access, not an automatic safety guarantee: verify the exact Buffer
type and length before constructing the span, do not retain its raw pointer
after the call, and do not process the same backing store concurrently from
another thread or while a pooled receive slot can be reused. It avoids a
payload copy/reallocation for this method but still crosses the JS/native
boundary and creates wrapper/result/runtime overhead. The sample method is
illustrative, and the repository's existing addon is a Node-API C interface,
not a node-addon-api `ObjectWrap`; expose this in a separate compatible
target or follow the project's established binding style rather than adding a
second module initializer to the same translation unit.

The wrapper's `addExactMatchRule` also converts the JS string to a native
`std::string` and appends a vector-backed rule, which may allocate or throw.
Catch/report allocation or conversion failures using the addon conventions,
reject empty and over-limit rules, and freeze or synchronize the ruleset
before any concurrent scan. Do not mutate rules while a connection is using
the shared engine. A synchronous `redactInPlace` keeps the JS call frame
active during scanning, but it can block the event loop; if future work moves
to a worker, use a documented backing-store retention/lifetime mechanism and
prevent JavaScript mutation or pool reuse until completion.

The short-payload test is particularly important because the proposed
scanner currently forms an out-of-bounds pointer for lengths below 64. A
successful expected-output assertion does not prove absence of an overread or
undefined behavior. Exercise the scanner natively under address/undefined
behavior sanitizers or with guard-page-backed buffers, in addition to
functional output checks. Add explicit 63-, 64-, and 65-byte inputs and
matches in the final scalar tail, exactly at the last legal start offset, and
crossing the 64-byte boundary. The 128-byte test's crossing token at offset
55 is within the valid payload and should be checked along with adjacent
bytes.

The overlap test is not a robust specification of "overlapping prefixes":
its first rule replaces `API_KEY_PROD` before the second rule scans, while the
later `API_KEY` occurrence is a distinct match. It demonstrates sequential
rule interaction, but not overlapping matches within one input occurrence
or equivalence between scalar and vector paths. Add cases with two actual
overlapping occurrences and pin down the intended match policy before
asserting exact output.

The benchmark should not be a timing-gated correctness test. It includes
100 MB of JS `Buffer.from` copying, uses nondeterministic `Math.random()`
placement, and labels a fixed 100 ms threshold a "FIPS threshold" without a
defined basis. JIT warmup is not relevant to the native scanner's compiled
code, and the test's reported throughput includes the copies. Move performance
measurement to a separate opt-in benchmark, use deterministic fixtures,
report scanner-only and end-to-end costs separately, and avoid flaky
machine-independent pass/fail latency assertions. The unused `crypto` import
can also be removed from the proposed test.

The proposed `bench_rcu_dlp.mjs` is not present or runnable in this checkout:
the `lattice_native_v2` addon, DLP wrapper, `ZeroCopyUdp`, and benchmark file
do not exist. Even once wired, the two runs do not establish an RCU
lock-free guarantee or compare RCU with `std::shared_mutex`; they only time
one implementation under two different workloads. Throughput similarity
cannot prove absence of locks, and UDP success counts cannot reveal which
internal operation blocked. Use direct atomic lock-freedom evidence and
profiling for implementation claims, and a controlled lock-based reference
if comparing synchronization strategies.

The network workload also has no bounded-loss accounting. It resolves only
when `receivedCount === BATCH_SIZE`; any dropped packet leaves the promise
pending forever, while extra warmup or late packets can make the count skip
the equality. Add readiness synchronization, per-batch IDs or isolated
receiver state, sent/received/drop counters, a timeout, and `try/finally`
cleanup for timers, sockets, and native shutdown. `dgram.send` completion
does not guarantee delivery, and the UDP payload is not a valid authenticated
`0x0005` frame, so this bypasses the proposed ingress pipeline.

The reused payload is all `0x41`, and the only initial rule is absent from
that payload. The measured callback therefore does not exercise a redaction
match or representative scanner work. Conversely, every millisecond the
writer adds another unique rule and the RCU implementation clones the entire
growing ruleset; this is an unbounded memory/workload-growth test, not a
steady-state comparison. Bound rule count, report the actual ruleset size,
use matched and unmatched deterministic payloads, and report latency
distributions, CPU, allocations, and packet loss across repeated runs. Keep
injection cost separate from reader scan cost and state whether traffic
callbacks execute on libuv workers or the V8 event loop.

The claim that readers remain "entirely unaware" is too strong: readers can
observe different immutable snapshots depending on when they load the
pointer, and shared-pointer reference-count/reclamation costs may affect
latency. Define the update visibility point and measure reader tail latency
during bounded updates; do not infer no blocking, no packet drops, or
lock-free progress from a lack of crashes.

The revised `bench_rcu_dlp_v2.mjs` fixes the earlier unmatched-payload and
unbounded-rule-growth issues in concept, but its packet loop cannot produce
the claimed successful ingress batch. `sealApplicationDatagram` is called
once, so all 50,000 sends carry the same authenticated sequence number.
After the first successful delivery, replay protection must reject the rest.
The benchmark increments `receivedCount` only for success, then waits forever
for 50,000 successes. Generate a fresh authenticated datagram with a unique
sequence for every send (or use a test-only batch sealer that preserves the
production sequence/nonce rules), and ensure the receiver's replay state is
fresh for each measured batch.

The original ciphertext buffer itself is not necessarily mutated by UDP send,
because the receiver gets its own datagram storage; however, sending the same
ciphertext still replays the same sequence and nonce. Do not solve this by
changing only the cleartext sequence/header: the header is AEAD AAD, and a
new sequence also requires a nonce consistent with that sequence and a valid
tag. Account for the CPU and JS/native overhead of generating distinct
packets separately from receive/DLP throughput, or pre-generate an adequately
large unique packet corpus.

`setRules()` is not O(1) end-to-end. Only publishing an already-built
immutable snapshot may be an O(1) pointer operation; converting 101 JS
strings and constructing/copying the native vector is O(total rule bytes)
and allocates. The old snapshot's destruction/reclamation may also occur on
the writer or reader thread. Label the workload accordingly, measure update
latency and reclamation separately, and define ownership/exception behavior
for the added native API. Alternating two rulesets also tests only atomic
snapshot publication, not concurrent writers or correctness of updates that
overlap.

The proposed `set_rules()` implementation builds a replacement vector before
publishing it, which avoids exposing a partially populated ruleset to readers.
However, it is not a single allocation: `reserve()` allocates the outer
vector, and each `pattern.assign()` can allocate separate token storage;
conversion from the V8 array allocates `std::string` values as well.
Construction is O(total input bytes) in time and memory. Only the atomic
publication itself is constant-time in the usual complexity model, and even
that operation may decrement the old shared pointer and trigger reclamation.
Do not claim the entire operation is O(1) or that V8 GC reclaims native
vectors predictably.

Define `setRules` as replacement semantics and make the update failure
atomic: validate every entry and build the complete candidate before
publishing; on any type, size, or allocation error retain the old ruleset and
return an explicit error. The wrapper currently silently skips non-string
array entries, accepts unbounded count/length, and passes empty strings for
the native layer to silently discard. Reject sparse/non-string entries and
invalid or over-limit rules rather than committing a surprising partial set.
Apply limits to UTF-8 bytes (the scanner's representation), not only JS
UTF-16 code units, and define duplicate handling and the meaning of the
reported active-rule count.

Concurrent `set_rules()` calls are individually atomic stores but are
last-writer-wins full replacements; they do not merge. If callers expect
updates to compose, serialize writers or use a correctly retried CAS update.
The mutable vector must never be exposed after publication. Ensure an old
snapshot remains alive until each reader finishes, and account for the fact
that whichever thread releases the final `shared_ptr` may perform
destruction/deallocation. A `setRules` API must not be added to this
repository's `src/addon.cpp` by copying the sample: the existing file uses
the C Node-API (`napi_*`), whereas the sample is a separate node-addon-api
`Napi::ObjectWrap` design and the v2 DLP wrapper is not present.

The benchmark still lacks a timeout and robust batch accounting. `receivedCount`
is not reset/read in a way that yields a valid baseline drop count: after a
successful batch it equals `BATCH_SIZE`, so `BATCH_SIZE - receivedCount`
reports zero regardless of packets lost before that success threshold. With
loss, the awaited benchmark never finishes; with late/duplicate callbacks,
batch attribution is ambiguous. `mitata` may invoke a benchmark function
multiple times, so receiver state, replay state, injection intervals, and
batch completion must be scoped per iteration. Add a timeout, unique
datagram/batch identifiers, sent/received/AEAD/replay/drop counters, and
`try/finally` cleanup. Do not label missing successes as OS socket-buffer
drops without platform telemetry that establishes the cause.

The code assumes unverified APIs and lifecycle behavior: `ZeroCopyUdp.start`
is awaited as a readiness callback, `onData` is assigned directly, and
`shutdown()` is not awaited. Confirm those contracts and hold the slab until
native close and queued callbacks complete. Its hard-coded 50,000-packet
burst is likely to measure sender/socket buffering and loss as much as DLP;
use paced or backpressured sending, smaller calibrated batches, and report
latency distributions plus throughput, CPU, allocations, and loss. Verify
that payload matches are actually redacted and the ruleset snapshot used by
each ingress operation is observable for test purposes without exposing
secret values.

The client needs replay state scoped to the connection and transport epoch,
but it MUST NOT drop solely because an unauthenticated cleartext sequence
number appears below the floor or already present in the bitmap. Such a
pre-AEAD drop lets forged frames suppress legitimate traffic. Authenticate
the frame first, then atomically check-and-commit the sequence and release
plaintext only if both succeed. Any pre-auth replay inspection must be
read-only and advisory, and must not reject on this direction unless a
separate authenticated binding makes that decision safe.

The supplied `ClientReplayWindow` has no epoch field, and the parser does
not validate the incoming epoch against an accepted window. A conforming
implementation must bind each replay window to its `connection_id`,
direction, and `transport_epoch` (or use an explicitly defined shared
cross-epoch sequence space); otherwise key changes can leave replay state
from one epoch incorrectly applied to another. The accepted epoch window,
creation, rollover, overlap, and retirement behavior must be specified.

The suggested client pipeline's tentative pre-check therefore MUST NOT
silently drop on a cleartext sequence number before AEAD verification.
Perform any duplicate/old-sequence lookup as a read-only optimization only;
authenticate the frame, then atomically recheck and commit the sequence.
Wipe decrypted plaintext and do not deliver it if the commit reports a
duplicate, stale sequence, or synchronization failure. This prevents
unauthenticated sequence spoofing and concurrent duplicate deliveries.

For `0x0004`, the nonce is not transmitted. The receiver constructs it by
XORing the big-endian sequence into the low eight bytes of the base nonce:
12 bytes for IETF ChaCha20-Poly1305, or 24 bytes for XChaCha20-Poly1305.
The sequence MUST NOT repeat under one directional key/nonce base, and MUST
NOT wrap. A new `server_boot_id` changes the derived traffic key with
overwhelming probability, so a restarted server can begin a new sequence
space; this is not a mathematical zero-collision guarantee. The boot ID must
be durably associated with resumed session state on the client and shared
consistently by every server worker using that key. If a client cannot
authenticate or retrieve the current boot ID, it must establish fresh
session state rather than guess or trial multiple IDs.

The latest parser sketch fixes the previous pre-auth replay rejection by
performing AEAD verification before the window commit. Its `atomic_flag`
serializes the post-auth check-and-update, its connection ID and active-epoch
checks scope processing to a local connection state, and it clears output
offsets on entry. Its bytewise big-endian XOR into bytes 16-23 matches the
proposed XChaCha nonce construction.

The sketch does not, however, demonstrate authenticated suite negotiation:
`cipher_suite` is only a local field, suite `0x0002` is hard-coded as the
default and sole accepted suite, no suite identifier appears in the frame or
shown authenticated handshake transcript, and the derivation helper remains
the 56-byte XChaCha variant without a suite input. The suite registry and
negotiation transcript must be specified, and the selected suite included
in the KDF before claiming downgrade resistance or cross-suite separation.
Connection ID, active epoch, and suite fields must remain immutable while
ingress calls use them, or lifecycle changes must synchronize with the
entire parse/authenticate/commit operation. Otherwise an epoch rollover can
race key derivation and window commit even though the bitmap update itself
is locked. The spinlock is unbounded and may suffer contention or priority
inversion; all accesses to the window floor and mask must continue to use
the same lock. The snippet also relies on surrounding definitions and
includes (including `std::endian`, KDF label, status/constants, and byte
readers). These details must be resolved and tested before the sketch is
implementation guidance.

The newer `0x0005` ingress sketch correctly checks version, frame type,
epoch, and connection ID before interpreting payload framing, and its header
is used as AEAD AAD. Its pre-authentication replay check only reads the
window and rejects values already recorded as duplicate or stale. Provided
the window is monotonic and connection resets are synchronized, that
read-only fast rejection cannot be used to advance replay state and does not
reject a new in-window sequence. It will not filter forged future sequence
values; those still require AEAD verification. The post-authentication block
updates the bitmap but never checks
whether the authenticated sequence is already present or stale at commit.
Two concurrent copies can both pass the pre-check, authenticate, then each
unconditionally OR the same bitmap bit and return success. Sequence zero is
also repeatedly accepted even sequentially: the initial `highest_rx_seq_no`
is zero, the pre-check deliberately exempts equal zero, and the post-auth
commit sets bit zero without checking it on later commits. The commit must
atomically re-evaluate the full window and report duplicate/stale/far-ahead
failure to every losing caller; wipe the in-place plaintext and expose no
payload offsets on failure. Initialize the bitmap/state so the first valid
sequence has unambiguous acceptance semantics.

The candidate has no sequence ceiling or maximum datagram-size check, even
though these are required elsewhere in the draft. Enforce the selected
sequence ceiling before nonce use, and reject oversized frames before
deriving payload length. Define accepted forward jumps and stale-window
behavior, then test sequence zero, exact duplicates, concurrent duplicates,
out-of-order unseen values, stale values, maximum forward jump, ceiling, and
integer-boundary cases. Its `atomic_flag` is a spinlock, not a lock-free
sliding window; contention and unbounded spinning need analysis, and every
window read/write must stay synchronized. The code only calls the x86 pause
intrinsic conditionally and has no wait/yield strategy for other targets.

The revised CAS candidate addresses the earlier duplicate-commit race: after
successful authentication, each CAS retry recomputes the window update from
the latest observed state and rejects a sequence that another thread already
committed. The sequence-zero case is also handled by the initially clear
bitmap: the first authenticated zero sets bit zero and later copies are
rejected. The pre-auth snapshot check is read-only, so it does not let a
forged high sequence advance the window. It also does not "instantly drop"
forged high sequences: values above the observed high-water mark pass that
check and still incur AEAD verification. This tradeoff avoids unauthenticated
state mutation; it cannot eliminate CPU exhaustion from a flood of
well-formed, unauthenticated datagrams.

The shown `compare_exchange_weak` uses `memory_order_release` on success and
`memory_order_acquire` on failure. That pairing is invalid: failure ordering
cannot be stronger than success ordering. Use `acq_rel`/`acquire`, or
`relaxed` for both if the replay-window atomic is the only synchronized
object; the comment claiming release publishes the private decrypted buffer
is not a sound reason for this ordering. Any publication of payload or
connection state needs its own documented synchronization. Check required
size/alignment and lock-freedom on supported targets, and account for toolchain
and linker support: `std::atomic<ReplayWindow>::is_always_lock_free` is an
implementation/platform property, not a portable guarantee that emits
`CMPXCHG16B`. A target lacking it will fail the assertion, while merely
having that CPU instruction does not prove the standard library uses it.
Even a lock-free CAS only guarantees system-wide progress for the atomic
operation, not fairness for each caller or freedom from OS descheduling;
authentication and redaction remain potentially blocking work.

The snapshot can become stale while AEAD runs, but the post-auth CAS loop
correctly reloads and revalidates after a failed CAS. That correctness depends
on the window being monotonic and on connection/epoch rollover being
synchronized with all in-flight ingress. The commit currently accepts any
authenticated forward jump below the sequence ceiling; specify and enforce
the maximum jump (or explicitly define that policy) so one authenticated
far-future packet cannot unexpectedly evict otherwise acceptable
out-of-order traffic. Also enforce the protocol's maximum datagram size
before payload processing. Preserve zero outputs and wipe plaintext for
post-auth replay rejection and every DLP failure; make DLP execution
non-throwing or handle errors explicitly rather than allowing an exception
to escape a `noexcept` ingress function.
Tests should verify forged future sequences leave the window unchanged,
already-committed duplicates are fast-rejected without mutation,
concurrent identical authenticated packets yield exactly one success,
CAS retries handle concurrent advancement, and a valid unseen out-of-order
sequence within the window is accepted.

The proposed `test_replay_window.cpp` is useful as a starting point, but it
does not yet validate all the claims in its introduction. The corrupted
sequence-1 packet only shows that a failed authentication does not advance
the initial window; it does not exercise the pre-auth fast path against a
forged future sequence, nor concurrent copies of the same authenticated
datagram. Add explicit assertions that a corrupted high sequence leaves the
window unchanged and its valid counterpart is still accepted, and synchronize
multiple workers on the same valid packet while asserting exactly one
success. Also verify a packet outside the current window and an unseen
in-window out-of-order packet.

The shuffled unique sequences do exercise concurrent updates and should all
fit in a 64-entry window, but `std::random_device` makes ordering
non-reproducible and does not guarantee high CAS contention. Use a fixed seed
for repeatable correctness coverage, and keep a separate stress/benchmark
mode if scheduler contention or throughput is the measurement goal. The
final bitmap assertion also assumes every sequence 1 through 60 is committed;
make its mask construction safe for any configured packet count (shifts by
64 or more are undefined).

As written, `using namespace client` and `using namespace server` make the
identically named `CLIENT_FRAME_HEADER_SIZE` and `OUTER_TAG_SIZE` constants
ambiguous in `generate_valid_datagram`; qualify them or avoid importing both
namespaces. Plain `assert` checks disappear when `NDEBUG` is set, so ensure
the test target keeps assertions enabled or uses a test framework whose
checks remain active in release configurations. A per-test generated client
state is safe here because each invocation uses a distinct sequence, but
duplicate tests must preserve an original ciphertext copy: ingress decrypts
the payload in place, and the same buffer is no longer a valid ciphertext
after a successful call.

The compiler instructions overstate portability. `-mcx16` requests a
particular x86 instruction from GCC/Clang, but does not guarantee that the
standard library implements `std::atomic<ReplayWindow>` as always lock-free
or linkable on every target; inspect the actual compiler/library result and
link requirements. `-mcx16` makes the instruction available to code
generation; it does not force the standard library's `std::atomic` lowering
to use it. Likewise, `-latomic` may be needed for compiler atomic helpers on
some targets, but a helper-backed atomic is not necessarily lock-free.
Confirm `is_always_lock_free` and runtime `is_lock_free()` for the exact
compiler, standard library, ABI, and target, and inspect generated code or
the helper implementation. The assertion should fail the build rather than
silently accepting a lock-backed implementation if lock-freedom is a hard
requirement.

The proposed Linux settings do not automatically apply to other POSIX
targets, and the macOS flags only make sense for an x86-64 build. Apple
silicon cannot execute `CMPXCHG16B` or AVX-512, and `-mcx16`/AVX-512 flags
cannot turn an arm64 target into an x86 target. Rosetta is not a substitute
for an explicitly supported and tested x86-64 deployment. Ensure node-gyp
actually forwards the Xcode settings to the C++ compile invocation and test
each supported architecture/toolchain.

On Windows, `/arch:AVX512` is unrelated to enabling 128-bit compare-exchange,
and AVX2/AVX-512 are not substitutes for validating `CMPXCHG16B` support.
MSVC's `/arch:AVX512` availability is toolset-dependent; it also permits
AVX-512 code generation, which can fault on CPUs lacking the emitted
features. Separate optional DLP acceleration from baseline protocol code
with runtime dispatch (including BMI1 where used), or explicitly constrain
and check the supported CPU set before entering optimized code. A compiler
flag is not runtime feature detection.

The proposed `binding.gyp` target is not an edit to the current build: this
repository has no `lattice_native_v2` target, no node-addon-api dependency
declaration, and the existing addon source/build uses a different setup.
Adding a second target that reuses `src/addon.cpp` would need an explicit
compatibility review rather than assuming the shown includes and exports
exist. The test command likewise assumes installed headers and a
`libmonocypher` library, while this repository builds its vendored sources
directly and currently has no v2 headers or replay test target. Do not
present the configuration or test as runnable in this checkout until the
implementation, dependency linkage, target-specific flags, and test
registration exist.

The standalone CMake proposal also does not guarantee that it builds with the
"exact same" ISA configuration as a Node-API addon: it is a separate build
graph with independently selected compiler, standard library, target
architecture, and options. Applying `add_compile_options()` globally is too
broad here: the options can affect C as well as C++ compilation, even though
`-std=c++20` is C++-only, and can compile the vendored crypto and test support
with AVX-512 instructions. Prefer target-scoped options and C++-language
generator expressions; keep baseline transport/crypto code at the deployment
baseline and isolate AVX-512 DLP code behind runtime dispatch or an explicitly
checked hardware requirement. Do not add ISA flags to all targets merely to
build one test.

The compiler-ID condition selects a flag spelling, not a supported
architecture or runtime CPU. `GNU|Clang|AppleClang` may target arm64, where
`-mcx16` and AVX-512 are not applicable; gate x86-only flags on the configured
target processor and fail configuration clearly for unsupported combinations.
`CMAKE_CXX_STANDARD` does not select the C standard for the vendored C source.
`Threads::Threads` is appropriate for the threaded test, but it does not
provide C++20 library support or make 128-bit atomics lock-free. As with the
node-gyp proposal, verify the atomic property and generated code for each
supported toolchain rather than inferring it from a successful configure or
build.

This checkout has no root `CMakeLists.txt`, no proposed v2 replay headers,
and no `test/test_replay_window.cpp`; only the existing node-gyp native tests
are present. The sample's `deps/monocypher/monocypher.c` path exists, but
that alone does not make the target buildable. Its `src` include path and
link dependencies must match the eventual header layout (including the DLP
and Monocypher declarations), and it must be registered only after the
actual v2 implementation and test are added. Keep this CMake setup a
non-normative proposal, not a runnable command for the current repository.

The DLP step is correctly placed after successful AEAD in the shown flow,
but replay commit must itself succeed before redaction result/offsets can be
published. If DLP cannot run or fails, the packet must fail closed, wipe
plaintext, and leave outputs zero. The shown function is `noexcept`, while
the proposed DLP engine may depend on mutable vector-backed rules and could
throw during configuration or have races during scans; finalize and safely
publish an immutable ruleset before ingress. The API must also validate
`datagram` size and all pointer/span preconditions and define the AEAD
failure wipe behavior for zero-length payloads.

**Security and implementation audit of these candidates:**

- In the common-header initiation/response pair, a fresh random
  `client_handshake_id` correlates the response without exposing the
  server-assigned `connection_id` in `0x0003`; it does not prevent traffic
  analysis or guarantee unlinkability. The compact initiation/response pair
  instead proposes a client-generated `connection_id`. These are competing
  ownership models: the selected format must consistently bind the ID in
  the response and inner ticket, and implementations MUST NOT mix them.
- The compact 794-byte `0x0001` proposal is a distinct alternative to the
  828-byte common-header initiation. Its suite-in-transcript binding only
  detects tampering if the response authenticates the same transcript; it
  does not authenticate an unauthenticated ML-KEM public key or server
  identity. Its transcript omits the epoch and protocol version, and the
  parser does not enforce epoch policy. The client-proposed connection ID
  also conflicts with the server-assigned ID in the response/ticket model.
- The compact parser's resume-key label is 35 bytes, not its stated/copied
  34; using 34 omits the final byte. Its derivation also differs from the
  registered `HANDSHAKE-RESUME` construction. Correct the encoding,
  reconcile the KDF, and provide KATs before adopting it. Exact-size errors
  should distinguish undersize from oversize; returning `BufferUnderflow`
  for every non-794-byte input obscures malformed/oversize input.
- The proposed initiation processor does not authenticate a server response
  or demonstrate the client's matching encapsulation/transcript flow, so it
  does not by itself close suite negotiation. Its `noexcept` function calls
  `std::make_unique`, which can throw and therefore terminate on allocation
  failure; use a non-throwing allocation/error path or remove `noexcept`.
  Clear output state/key on entry and define failure ownership. ML-KEM
  decapsulation's implicit rejection does not provide a ciphertext-validity
  boolean; acceptance must be established by the authenticated response,
  not by treating decapsulation success as peer authentication.
- The proposed bifurcated schedule correctly separates response protection
  from resumed traffic by distinct SHAKE labels: `HANDSHAKE-KEY` is 38 bytes
  and `RESUME-KEY` is 35 bytes. The sample still specifies `RESUME-KEY` as
  34 bytes, which truncates the domain separator and must be corrected.
  Its bifurcated `K_client_resume` also differs from the registered
  `HANDSHAKE-RESUME` input; select one exact schedule and provide matching
  KATs rather than mixing them.
- The latest `0x0003` parser claims `ProcessingHandshake`, hashes the
  original ciphertext before in-place decryption, enforces sequence zero,
  caches the digest only after authentication, and publishes the boot ID,
  ticket, and payload outputs before the release-store to `Established`.
  This fixes the previously noted output-publication ordering issue for
  consumers that acquire the established state. Caller-owned output buffers
  still require a clear ownership/lifetime rule; a release store does not
  make unsynchronized concurrent access to those buffers safe. Rollback
  must remain conditional on the processing attempt's ownership. The server
  must retransmit the exact cached ciphertext under the single-use
  handshake key/IV.

  #### Node-API ownership and buffer boundary

  A Node-API `ObjectWrap` is a reasonable way to associate a native connection
  object with JavaScript reachability, but it does not itself make the
  connection state thread-safe or validate input buffers. The supplied
  `LatticeConnectionV2` sketch is illustrative and MUST validate argument
  count/type and exact lengths before every access: 16-byte connection ID,
  32-byte handshake key, suite-appropriate nonce (24 bytes for XChaCha),
  32-byte resume key, and 16-byte boot ID. The datagram size must also be
  checked against the protocol's minimum and maximum before parsing. Numeric
  epoch and suite arguments MUST be finite integral JavaScript Numbers within
  their respective `uint32_t` and `uint16_t` ranges before conversion; an
  integer conversion API alone may truncate fractional values or convert
  non-finite/out-of-range input. A safe extraction helper first obtains the
  Number as a `double`, checks `std::isfinite(d)`, `d >= 0`,
  `std::floor(d) == d`, and `d <= max_bound`, and only then converts to an
  unsigned integer. The epoch and suite bounds are exactly representable as
  JavaScript Numbers. The chosen suite must be authenticated by the handshake,
  not only set in the constructor.

  The synchronous example passes the JS Buffer's backing store directly into
  native code, and the parser decrypts the datagram in place. Therefore the
  input `datagramBuf` is modified on success and may be wiped on authentication
  or replay failure; this observable mutation must be documented. The shown
  `Buffer::Copy` for payload is a copy, not zero-copy access. Returning
  `(payloadOffset, payloadLength)` instead allows the caller to create
  `datagram.subarray(payloadOffset, payloadOffset + payloadLength)`. This is a
  shared view, not an independent payload: it observes later writes and wipes
  to the datagram's backing store. The caller must keep the datagram/view
  reachable for use and must not reuse or wipe that storage while the payload
  is needed. For a synchronous parser, the addon need not retain a native
  pointer after returning; asynchronous processing requires a separate,
  documented backing-store lifetime strategy.

  The constructor's `memcpy` must occur only after verifying that the
  connection-ID Buffer has exactly 16 bytes. Likewise, the method must verify
  datagram/key/IV sizes before calling `.Data()` or passing pointers to
  cryptographic code. Output buffers should be returned only on success and
  must not expose partially initialized contents on exceptions or native
  errors. Native allocation failures must be surfaced as JavaScript errors;
  do not allow exceptions to cross a `noexcept` ingress boundary or be silently
  converted to success-shaped results.

  In the repository's node-addon-api API, `SetInstanceData<T>(ptr)` defaults
  to `DefaultFini<T>`, which deletes the pointer at environment teardown.
  Thus `env.SetInstanceData<Napi::FunctionReference>(constructor)` is
  sufficient for this owning allocation when supported by the configured
  Node-API version; use a custom finalizer only when a different cleanup
  policy is required. Do not copy this assumption to APIs or versions with a
  different contract. For asynchronous/Promise-based processing, do not
  capture raw `Napi::Buffer` pointers or a raw `ObjectWrap`/state pointer in a
  worker. Copy or retain the input backing store using a documented Node-API
  lifetime mechanism, and keep the connection object alive or use
  independently owned shared state. Serialize handshake/application state
  transitions across workers; JavaScript object reachability alone does not
  prevent concurrent native calls or finalization races. Keep all N-API value
  creation and mutation on a permitted JavaScript thread.
- Replaying a valid `0x0001` can repeat ticket issuance and replay early
  application data. After handshake AEAD succeeds, the server needs bounded
  duplicate-request handling before performing non-idempotent effects or
  minting a new response. If it returns a cached response, that response
  must be byte-identical. The cache's lifetime, capacity, restart behavior,
  and failure policy are unresolved; declaring early data “idempotent” is
  not itself a replay defense.
- The earlier `HANDSHAKE-S2C` context and response-sequence-zero proposal
  repeats its response key/nonce when the same valid initiation is processed
  again. It is superseded by the bifurcated `HANDSHAKE_KEY`/
  `HANDSHAKE_IV` candidate, but that candidate has the same single-use
  constraint: duplicate handling must return the exact cached ciphertext,
  never encrypt changed plaintext under the same key/nonce.
- Omitting the ticket block and explicit nonce from `0x0004` gives 48 bytes
  of header/tag overhead and a 1,152-byte payload at a 1,200-byte UDP-payload
  limit. The client-side sliding replay window must not reject based only
  on the unauthenticated cleartext sequence; authenticate first, then
  atomically recheck/commit and deliver only on successful commit. The
  revised SHAKE-256 KDF binds the resume secret, direction, connection ID,
  boot ID, and transport epoch, pending cryptographic review and test
  vectors. The server boot ID must be delivered and retained consistently;
  its randomness provides overwhelming-probability key separation, not an
  absolute zero-collision guarantee.
- The `0x0004` candidate's removal of the explicit nonce requires the
  authenticated handshake response to carry the 16-byte `server_boot_id`;
  the earlier response layout carried it encrypted and had a 228-byte
  minimum; the latest compact response carries it in the authenticated
  48-byte header and has a 176-byte fixed overhead including the ticket.
  A client retaining an older boot ID cannot decrypt new-boot `0x0004`
  traffic and must perform a fresh authenticated handshake. The server must
  not silently fall back to the old key after a restart.
- The earlier compact `0x0003` parser reused `derive_client_rx_material`
  and the `0x0004` replay window; that would reuse a key/nonce when both
  sequence numbers are zero and mix handshake with application replay
  state. The bifurcated `HANDSHAKE_KEY`/`HANDSHAKE_IV` proposal corrects
  the key-domain issue and replaces the response sliding-window check with
  a state transition. The latest parser claims `ProcessingHandshake` before
  validating, and publishes `Established` after AEAD success, which avoids
  premature establishment. Its retransmission hash is computed after
  in-place decryption, however, so it will not match the original wire
  ciphertext on retry; hash the original datagram before opening and retain
  that digest only after authentication. Enforce the proposed response
  sequence zero. Successful key confirmation proves possession of the KEM
  shared secret, not server identity unless the ML-KEM public key is
  authenticated.
- The parser's 176-byte fixed layout arithmetic is consistent: 48-byte
  header + 112-byte ticket + 16-byte tag, leaving 1,024 optional payload
  bytes under a 1,200-byte cap. Its ticket is confidential only because it
  lies inside the outer AEAD-protected payload; the ticket must still use
  the defined inner STEK encryption/authentication. The parsed
  `connection_id`, epoch, suite, and transcript must match the authenticated
  initiation state before outputs are accepted.
- The latest `0x0004` parser fixes the pre-auth replay drop and uses a
  post-auth spin-locked window commit and clears output offsets on entry.
  However, its suite value is only local configuration, not demonstrated
  authenticated negotiation; the parser accepts only XChaCha suite `0x0002`
  and its derivation helper omits a suite ID. The suite must be negotiated
  in authenticated handshake data and bound into the KDF. Connection,
  epoch, and suite state must be immutable during ingress or protected by
  lifecycle synchronization. All reads and writes of the window floor and
  mask must use the lock, and the unbounded spinlock needs
  contention/priority-inversion analysis.
- Neither the 828-byte common-header initiation/228-byte response nor the
  794-byte compact initiation/176-byte fixed-overhead response establishes
  an anti-amplification bound by itself. Optional response data can increase
  the response size. Before client address validation, the server needs an
  explicit response-size/rate limit or a validated return-routability step.
  No amplification ratio is established by these frame sizes.
- The handshake KDF registry has eight derivations through the two
  directional resumption entries, not “seven”; adding the replay-index
  construction makes nine. The supplied label lengths for
  `HANDSHAKE-C2S` and `HANDSHAKE-S2C` are both 38 bytes.
- The supplied response-unpacking sketch is not C++20 as written because
  `std::byteswap` is C++23. More importantly, Monocypher's
  `crypto_aead_unlock` is the XChaCha20-Poly1305 API with a 24-byte nonce;
  passing the 12-byte field at `raw + 32` is invalid regardless of the
  separate safe 12-byte comparison helper. The chosen IETF AEAD API must be
  explicit and used for both sealing and opening.
- The response-unpacking sketch does not derive or assign its
  `client_resume_key` output: it receives neither `ss` nor the KDF inputs as
  arguments. It also does not enforce the proposed zero response sequence
  or a configured maximum datagram size. Those checks and derivation must be
  implemented before its output structure can be trusted.
- Ticket issue epoch and salt, the inner assigned connection ID, timestamps,
  initial sequence baseline, reserved fields, and response epoch/sequence
  all require bounds and cross-field checks. The protocol must state whether
  `initial_seq_floor` seeds both direction-specific replay windows or whether
  each direction has a separate baseline; implementations must not assume
  the two sequence spaces share state.

Until these issues are resolved, none of `0x0001`, `0x0003`, or `0x0004`
should be treated as a normative encoding or implemented from the pasted
code. The 112-byte ticket and 0x0002 resumed-frame proposals remain separate
from this handshake-response proposal.

## 9. Security and compatibility status

This architecture has not received independent cryptographic or protocol
review and MUST NOT be treated as production-ready. It makes no claim of
sub-microsecond ingress or a particular speedup. Measurements must include
the actual ticket validation, AEAD, replay, and runtime costs on supported
hardware.

SPEC-LATTICE-WIRE-01 remains a separate protocol. V2 implementations MUST NOT
reinterpret v1 frames, and v1 implementations MUST NOT attempt to parse v2
frames. Shared cryptographic primitives do not make the wire formats
interoperable.

## 10. Optional 1-RTT session helper

`lib/crypto/OneRttSession.js` uses the addon's native 1-RTT state by default
when the state bindings are available. The addon exports
`createOneRttState(baseNonce[, initialTxSeq])`,
`resetOneRttReplayWindow(state)`, `sealOneRttFrame(key, state, plaintext[, aad])`,
`openOneRttFrame(key, state, sequenceNumber, sealed[, aad])`, and
`openOneRttFrameInPlace(key, state, sequenceNumber, sealed[, aad])`.
`destroyOneRttState(state)` explicitly wipes and invalidates the non-secret
state; its finalizer is a fallback. The state contains a 12-byte base nonce,
64-bit transmit counter/exhaustion state, and a 64-packet receive replay
bitmap, but no traffic key. The key may be a Buffer or a secure handle and
is read directly by the native AEAD operations.

Native receive processing inspects the sequence before IETF
ChaCha20-Poly1305 authentication and commits it only after authentication.
In-place success wipes the trailing tag; an unexpected commit failure wipes
the decrypted buffer before returning an error. When a caller injects a
custom JavaScript replay window, the helper keeps its JavaScript fallback and
wipes plaintext if that custom window rejects or throws during commit.
Replay-window comparisons are not claimed to be constant-time: sequence
numbers are public, while AEAD authentication is performed by the native
cryptographic implementation.

The state APIs are synchronous and not internally synchronized for concurrent
access. Keep each state owned by one execution context and serialize its
operations; process-local state does not coordinate replay defense across
workers, processes, or restarts. `resetOneRttReplayWindow` intentionally
clears replay protection and should be used only when the caller can safely
establish a fresh receive epoch (or in isolated benchmark/test state).

Callers MUST use distinct directional key/nonce pairs and MUST NOT reuse a
key/base-nonce pair across sessions or after sequence-state loss. The helper
does not derive directional keys or distribute base nonces. Its ownership
option defaults to destroying a supplied native secure handle (or wiping a
supplied Buffer) when `destroy()` is called; set `ownsKey: false` only when
the key lifetime is managed elsewhere.

The package declaration file `index.d.ts` brands secure-secret, replay-window,
and 1-RTT-state handles as distinct opaque types and declares the secure-output
overloads and session/epoch APIs. The package root `index.js` re-exports all
native addon bindings together with `EpochKeyManager`, `OneRttSession`, and
`SlidingReplayWindow`. `test/types_contract.test.mjs` checks those root and
native exports and the declared public class members against the runtime.
`test/vmlck_linux.test.mjs` verifies kernel `VmLck` accounting and deterministic
release on Linux; it is skipped on platforms without `/proc/self/status`.
