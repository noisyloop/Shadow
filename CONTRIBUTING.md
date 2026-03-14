# Contributing to Shadow

Shadow is a research-grade end-to-end encrypted messaging protocol. It implements the Signal Double Ratchet and X3DH handshake from scratch, with a sealed sender layer and a Nostr relay transport. This document covers everything needed to contribute code, tests, or documentation.

---

## Table of Contents

1. [Project Philosophy](#1-project-philosophy)
2. [Repository Structure](#2-repository-structure)
3. [Development Setup](#3-development-setup)
4. [Running the Test Suites](#4-running-the-test-suites)
5. [Contribution Guidelines](#5-contribution-guidelines)
6. [Cryptographic Change Requirements](#6-cryptographic-change-requirements)
7. [Code Style](#7-code-style)
8. [Pull Request Requirements](#8-pull-request-requirements)
9. [Security Vulnerability Disclosure](#9-security-vulnerability-disclosure)
10. [Roadmap](#10-roadmap)

---

## 1. Project Philosophy

**Minimal dependencies.** Every dependency is a potential supply-chain attack surface. Shadow deliberately limits its dependency set to well-audited, widely-deployed cryptographic libraries. The Python implementation uses only `cryptography` (PyCA) and `websockets`. The Rust implementation uses `x25519-dalek`, `ed25519-dalek`, `aes-gcm`, `hkdf`, `hmac`, and `sha2` — all from the RustCrypto family with extensive review histories. Do not add new cryptographic libraries without the process described in Section 6.

**Auditability over cleverness.** Code that can be audited by a cryptographer who is not a Rust or Python expert is more valuable than code that is clever. Prefer straightforward implementations that match the specification's pseudocode over optimized or abstracted versions. Optimize only when performance is a demonstrated bottleneck, and never at the cost of legibility of the security-critical path.

**No home-grown cryptography.** All cryptographic primitives (AES-GCM, HKDF, HMAC-SHA256, X25519, Ed25519) are delegated to audited libraries. The algorithms (Double Ratchet, X3DH, Sealed Sender) are Shadow's composition of those primitives, verified against the Signal protocol specifications and tested for correctness against the expected properties.

**Deterministic, auditable state transitions.** The ratchet state machine must be entirely reproducible from its serialized state. No hidden mutable global state. No randomness except where explicitly required (nonce generation, DH keypair generation). All randomness must use `os.urandom` (Python) or `OsRng` (Rust) — never a weaker source.

**Tests are not optional.** Every change to `core/`, `transport/`, `cli/src/crypto/`, or `mobile/src/crypto/` must include or update tests. PRs that reduce test coverage for security-critical paths will not be merged.

**The spec is authoritative.** `docs/PROTOCOL.md` is the canonical specification. The implementation follows the spec. If the implementation and the spec disagree, the spec is correct and the implementation must be fixed — unless the spec has a documented error, in which case the spec must be updated first.

---

## 2. Repository Structure

```
Shadow/
├── core/                      # Python reference implementation (Phases 0-3)
│   ├── ratchet.py             # Double Ratchet: KDF_RK, KDF_CK, encrypt, decrypt, state
│   ├── identity.py            # DeviceIdentity, SignedPreKey, OneTimePreKey, PreKeyBundle
│   └── x3dh.py               # X3DH send/receive, InitialMessage wire format
├── transport/                 # Python transport layer
│   ├── nostr.py               # BIP340 Schnorr, NostrEvent, NostrRelay, LocalRelay
│   └── sealed_sender.py       # ECIES, SenderCertificate, SealedEnvelope, seal/unseal
├── tests/                     # Python test suites (pytest)
│   ├── test_ratchet.py        # 8 tests: round-trip, forward secrecy, break-in recovery,
│   │                          #   out-of-order, AD binding, header integrity
│   ├── test_x3dh.py           # 4 tests: basic session, no-OPK fallback, SPK verification,
│   │                          #   OPK consumption
│   └── test_integration.py    # 6 tests: full stack X3DH + ratchet + sealed sender + Nostr
├── cli/                       # Rust CLI/TUI (Phase 4)
│   ├── Cargo.toml             # Dependency manifest
│   └── src/
│       ├── main.rs            # Entry point, clap CLI definition
│       ├── commands/          # init.rs, add.rs, key.rs, send.rs, recv.rs
│       ├── crypto/            # ratchet.rs, identity.rs, x3dh.rs (Rust ports of core/)
│       ├── transport/         # nostr.rs (tokio-tungstenite WebSocket client)
│       ├── tui/               # app.rs, ui.rs (ratatui TUI)
│       └── store.rs           # ~/.shadow/ key store and session persistence
├── mobile/                    # React Native / Expo app (Phase 5)
│   ├── App.tsx
│   ├── package.json
│   └── src/
│       ├── crypto/            # identity.ts, ratchet.ts, x3dh.ts
│       ├── store/             # keys.ts, messages.ts, contacts.ts
│       ├── screens/           # HomeScreen, ChatScreen, AddContactScreen, KeyScreen
│       ├── components/        # MessageBubble, QRDisplay
│       └── navigation/        # index.tsx
└── docs/
    ├── PROTOCOL.md            # Full cryptographic protocol specification
    └── THREAT_MODEL.md        # Threat actors, trust model, known weaknesses
```

**Key design constraint:** The Python `core/` module is the reference implementation and the target for cryptographic audit. The Rust `cli/src/crypto/` module is a production port. Both must implement identical semantics. If they diverge, the Python reference is authoritative.

---

## 3. Development Setup

### 3.1 Prerequisites

| Tool | Minimum version | Purpose |
|---|---|---|
| Python | 3.11 | Reference implementation, all tests |
| Rust | 1.70 (stable) | CLI/TUI production build |
| Node.js | 18 LTS | React Native / Expo mobile app |
| Expo CLI | 0.18+ | Mobile build tooling |

### 3.2 Python Environment

```bash
# From repository root
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate

pip install cryptography pytest websockets
```

The `cryptography` package (PyCA) is the only cryptographic dependency. It links to OpenSSL or BoringSSL and provides X25519, Ed25519, HKDF-SHA256, and AES-256-GCM. Do not substitute alternative Python cryptography libraries.

### 3.3 Rust Environment

```bash
# Install Rust via rustup if not present
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup default stable

cd cli
cargo build                     # debug build
cargo build --release           # optimised build (slower compile)
cargo run -- --help             # verify CLI is wired correctly
```

The first build downloads all crates from crates.io and compiles them. Subsequent builds are incremental. The `--release` build enables compiler optimizations; use it for performance testing only. Always run tests against the debug build to catch integer overflow and bounds checks.

### 3.4 React Native / Expo (Phase 5)

```bash
cd mobile
npm install
npx expo start                  # Metro bundler + QR code for physical device
npx expo run:ios                # Requires Xcode on macOS
npx expo run:android            # Requires Android Studio and SDK
```

The mobile app has not been published to app stores. It is a research prototype. Do not test it with real sensitive communications.

---

## 4. Running the Test Suites

All three test suites must pass before any merge.

### 4.1 Python Tests

```bash
# From repository root, with venv activated
python -m pytest tests/ -v
```

Expected output:

```
tests/test_ratchet.py::test_basic_round_trip                PASSED
tests/test_ratchet.py::test_multiple_messages_one_direction PASSED
tests/test_ratchet.py::test_alternating_conversation        PASSED
tests/test_ratchet.py::test_forward_secrecy                 PASSED
tests/test_ratchet.py::test_break_in_recovery              PASSED
tests/test_ratchet.py::test_out_of_order_delivery          PASSED
tests/test_ratchet.py::test_associated_data_binding        PASSED
tests/test_ratchet.py::test_header_integrity               PASSED
tests/test_x3dh.py::...                                    [4 passed]
tests/test_integration.py::...                             [6 passed]
18 passed in X.XXs
```

To run individual suites:

```bash
python -m pytest tests/test_ratchet.py -v       # Double Ratchet only
python -m pytest tests/test_x3dh.py -v          # X3DH only
python -m pytest tests/test_integration.py -v   # Integration (requires all layers)
```

### 4.2 Rust Tests

```bash
cd cli
cargo test                          # all unit tests
cargo test -- --nocapture           # include println! output
cargo test crypto::                 # crypto module tests only
```

### 4.3 Mobile TypeScript

```bash
cd mobile
npx tsc --noEmit                    # type-check without emitting
```

Jest integration is planned (issue #TBD). Until then, TypeScript strict mode type-checking is the gate for the mobile layer.

### 4.4 What Each Test Covers

**`test_ratchet.py`** — core Double Ratchet properties:
- Basic round-trip encryption and decryption.
- Multiple messages in one direction (chain advancement).
- Alternating conversation (DH ratchet on each reply).
- Forward secrecy: snapshot of old state cannot decrypt new messages.
- Break-in recovery: attacker with current state loses access after DH step.
- Out-of-order delivery: messages arrive and decrypt in non-sequential order.
- Associated data binding: wrong AD causes AEAD failure.
- Header integrity: modified header causes AEAD failure.

**`test_x3dh.py`** — X3DH handshake properties:
- Full session establishment with OPK.
- Fallback to 3-DH when no OPK is available.
- SPK signature verification: reject bundles with bad signatures.
- OPK is consumed and not reused.

**`test_integration.py`** — full protocol stack properties:
- Multi-turn conversation via sealed sender.
- Relay sees no plaintext sender identity in the sealed envelope.
- Tampered sealed blob causes authentication failure.
- Expired sender certificate is rejected on unseal.
- Full Nostr relay publish/receive round-trip via `LocalRelay`.
- Wire format serialization round-trips for `InitialMessage` and `SealedEnvelope`.

---

## 5. Contribution Guidelines

### 5.1 What Requires an Issue First

Open a GitHub issue before implementing any of the following:
- New cryptographic primitives or algorithms.
- Changes to the wire format of `Header`, `InitialMessage`, or `SealedEnvelope`.
- Changes to KDF constants (`HKDF_INFO_RK`, `X3DH_INFO`, `SEALED_SENDER_INFO`, HMAC `0x01`/`0x02` constants).
- Changes to the ratchet state machine (skip-message-key limits, DH ratchet trigger conditions).
- New dependencies in `core/` or `cli/src/crypto/`.
- Changes to the threat model documentation that add or remove security claims.

For everything else, implementation-level PRs without prior issues are welcome.

### 5.2 General Contribution Rules

- Match the style of the surrounding code. See Section 7 for per-language style guides.
- Do not introduce new mutable global state.
- Do not add `print` or logging of raw key material. Use truncated hex (first 8 bytes) for debugging at `DEBUG` level only.
- Keep commits focused. One logical change per commit. Conventional commit format (see Section 8).
- Update `docs/PROTOCOL.md` if the change affects the protocol wire format or key derivation. Update `docs/THREAT_MODEL.md` if the change affects the threat model.

---

## 6. Cryptographic Change Requirements

Changes to the cryptographic core (`core/`, `cli/src/crypto/`, `transport/sealed_sender.py`) are held to stricter standards than changes to UI, CLI, or transport glue code.

### 6.1 Spec Citation Requirement

Every cryptographic function, constant, and algorithm must cite its authoritative specification in a code comment. Examples:

```python
# Signal Double Ratchet spec §2.2
HMAC_CK_CONST = b"\x01"   # derive next chain key
HMAC_MK_CONST = b"\x02"   # derive message key
```

```rust
// X3DH spec §2.3: KDF(F || DH1 || DH2 || DH3 [|| DH4])
// F = 0xFF * 32 bytes (domain separator)
const X3DH_F: &[u8] = &[0xff; 32];
```

PRs without spec citations for cryptographic constants and algorithms will be sent back for revision.

### 6.2 Test Requirement for Cryptographic Changes

Any change to a cryptographic function must be accompanied by:
1. A unit test that verifies the change against known-good input/output pairs.
2. If the change affects an existing security property (forward secrecy, break-in recovery, AEAD binding), a regression test that verifies the property is preserved.
3. If the change introduces a new security property, a new test that explicitly validates it.

Tests must be written before the implementation is merged. Do not write "will add tests in follow-up PR" for cryptographic changes.

### 6.3 Adding a New Cryptographic Primitive

1. Open an issue describing: the primitive, the security problem it solves, the library you intend to use, and why the current primitives are insufficient.
2. Link to the library's audit reports, CVE history, and maintenance record.
3. Implement the primitive in a separate module with isolated unit tests.
4. Update `docs/PROTOCOL.md` with a new subsection under Section 2 following the existing format (summary table, parameter description, justification).
5. Update `docs/THREAT_MODEL.md` if the change affects the threat model (e.g., adding post-quantum security changes Section 3.5).
6. The change requires approval from at least two reviewers, at least one of whom has a published background in applied cryptography.

### 6.4 What Is Off-Limits Without a Protocol Version Bump

The following changes break interoperability between existing sessions and require a protocol version negotiation mechanism before they can be deployed:

- Changing the wire format of `Header` (40-byte layout).
- Changing the wire format of `InitialMessage` (field ordering, length prefixes).
- Changing the wire format of `SealedEnvelope` or the ECIES sealed blob.
- Changing any KDF info string (`ShadowRootKey`, `ShadowX3DH`, `ShadowSealedSender`).
- Changing the HMAC constants `0x01` / `0x02` used in `KDF_CK`.
- Changing the `MAX_SKIP` value (affects whether sessions can interoperate across library versions).

### 6.5 Code Review Requirements for Crypto Changes

Cryptographic changes must receive:

- At least two approving reviews.
- At least one reviewer must be a maintainer with demonstrated applied cryptography background (listed in the project maintainers file, once that exists).
- The PR must remain open for at least 72 hours after the last substantive change to allow for community review, regardless of approval count.
- The PR description must include: what was changed, why, the spec section it corresponds to, and the test cases added.

For changes that alter security properties (forward secrecy, break-in recovery, authentication), the description must also include a brief security argument — not just "this follows the spec" but an explanation of why the change preserves or improves the stated properties.

### 6.6 Key Hygiene Requirements

**Python:**
- Never store key material as strings. Keys are `bytes` objects with fixed length.
- Never log raw key material, even at `DEBUG` level. Log only `key[:8].hex() + "..."`.
- Keys stored in `RatchetState`, `DeviceIdentity`, `SignedPreKey`, and `OneTimePreKey` are plain `bytes` for serializability. Key objects (e.g., `X25519PrivateKey`) are created transiently and must not be stored or cached.
- After using a private key for DH, let the reference go out of scope immediately. Do not hold references across function boundaries.

**Rust:**
- All private key types use `[u8; 32]` arrays.
- Types that hold private key material should derive or implement `zeroize::Zeroize` and `zeroize::ZeroizeOnDrop` where the type allows it. The `x25519-dalek` `StaticSecret` type includes `zeroize` support when the `zeroize` feature is enabled (already in `Cargo.toml`).
- Do not `clone()` private key arrays except where unavoidable. If cloning is required, document why.
- Never log or format private key material, even with `{:?}`.

**TypeScript:**
- Keys are hex-encoded strings for store compatibility. They are decoded to `Uint8Array` immediately before use and not retained after.
- Use `crypto.getRandomValues()` for all randomness. Never use `Math.random()` near cryptographic operations.

---

## 7. Code Style

### 7.1 Python

- Format with `black` (line length 88). Run `black .` before committing.
- Sort imports with `isort` (compatible with `black`).
- Type-annotate all public function signatures. Return types are required.
- Docstrings for all public functions: one-line summary, then parameter/return description for anything non-obvious.
- `snake_case` for all names.

Example:

```python
def kdf_rk(root_key: bytes, dh_out: bytes) -> tuple[bytes, bytes]:
    """
    KDF_RK(rk, dh_out) -> (new_root_key, chain_key)

    Signal Double Ratchet spec §2.2.
    HKDF-SHA256 with the root key as salt.
    """
```

### 7.2 Rust

- Format with `cargo fmt`. CI enforces this.
- Lint with `cargo clippy -- -D warnings`. No warnings are allowed at merge time.
- `snake_case` for functions and variables, `CamelCase` for types and traits.
- `///` doc comments for all `pub` items. Include the spec reference in the doc comment.
- `//!` module-level doc comments describing the module's purpose and citing the spec.

Example:

```rust
/// KDF_RK — root key and chain key derivation.
///
/// Reference: Signal Double Ratchet spec §2.2
/// HKDF-SHA256(salt=rk, ikm=dh_out, info="ShadowRootKey") → 64 bytes → (new_rk, ck)
pub fn kdf_rk(root_key: &[u8; 32], dh_out: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
```

### 7.3 TypeScript

- Format with Prettier (default config). Run `npx prettier --write .` before committing.
- `strict: true` TypeScript. No `any`. No type assertions (`as T`) without a comment explaining why it is safe.
- React components: use `React.memo()` for all pure display components.
- Prefer `useCallback` and `useMemo` for functions and values passed as props.
- `camelCase` for functions and variables, `PascalCase` for types, interfaces, and components.

---

## 8. Pull Request Requirements

### 8.1 Checklist

Before opening a PR, verify:

- [ ] All Python tests pass: `python -m pytest tests/ -v` (18/18)
- [ ] All Rust tests pass: `cargo test` (cli/)
- [ ] TypeScript type-checks clean: `npx tsc --noEmit` (mobile/)
- [ ] No new Rust lint warnings: `cargo clippy -- -D warnings`
- [ ] Code formatted: `black .` (Python), `cargo fmt` (Rust), `prettier --write .` (TypeScript)
- [ ] Spec citations present for any new cryptographic code
- [ ] Tests added or updated for any changed cryptographic behavior
- [ ] `docs/PROTOCOL.md` updated if wire format or KDF changes
- [ ] `docs/THREAT_MODEL.md` updated if threat model changes
- [ ] Commit messages follow conventional commit format

### 8.2 Branch Naming

```
feature/<short-description>
fix/<issue-number>-<short-description>
docs/<section-name>
test/<what-is-being-tested>
```

### 8.3 Commit Message Format

Use conventional commits:

```
feat(ratchet): add configurable MAX_SKIP parameter
fix(x3dh): reject bundles where SPK signature is wrong length
docs(protocol): document AEAD associated data construction
test(integration): verify no-OPK fallback session survives multi-turn
refactor(crypto): extract concat_ad into shared helper
```

### 8.4 PR Description Template

```
## What
One paragraph describing what changed.

## Why
One paragraph describing the motivation. Link to the issue if one exists.

## Spec reference
Cite the specification section(s) this change implements or modifies.

## Security argument
For cryptographic changes: explain why this change preserves or improves
the security properties stated in docs/PROTOCOL.md.

## How to test
Steps to reproduce the test scenario manually, in addition to the automated tests.

## Checklist
- [ ] Tests added/updated
- [ ] Spec cited in code comments
- [ ] Docs updated
```

---

## 9. Security Vulnerability Disclosure

**Do not open a public GitHub issue for security vulnerabilities.**

### 9.1 Responsible Disclosure Process

1. Email `security@shadow-project.example` (placeholder — replace with actual address before publishing) with the subject line `[SECURITY] <brief description>`.
2. Include in the report:
   - Affected component(s) and the commit hash or version.
   - A clear description of the vulnerability and its cryptographic or security impact.
   - Steps to reproduce, or a proof-of-concept demonstrating the issue.
   - Your preferred contact method for follow-up.
3. You will receive an acknowledgement within **48 hours**.
4. We target a **90-day** fix timeline from the date of initial report. We will update you on progress and coordinate public disclosure timing with you.
5. If you do not receive a response within 48 hours, follow up via GitHub Discussions without revealing vulnerability details.

### 9.2 In-Scope Issues

The following categories are in scope for coordinated disclosure:

- Cryptographic protocol weaknesses: ratchet state machine, X3DH DH output construction, Sealed Sender ECIES, KDF domain separation.
- Key material leakage: logging, crash dumps, insecure storage of private keys.
- Authentication bypass: forged sender certificates, invalid SPK signature acceptance, header tampering that is not detected.
- Relay-side deanonymization beyond what is documented in `docs/THREAT_MODEL.md`.
- Wire format parsing vulnerabilities (integer overflow, out-of-bounds read, buffer mishandling).

### 9.3 Out-of-Scope Issues

- Denial of service against a relay you operate.
- Social engineering attacks.
- Vulnerabilities in third-party dependencies (report those to the upstream maintainer; link us to the report).
- Issues that require physical access to an unlocked device.

### 9.4 Recognition

With your permission, we will credit you in the release notes for the patched version. If you prefer anonymous recognition, state that in your report.

### 9.5 Note on Cryptographic Audits

Shadow is designed for a formal cryptographic audit and welcomes researcher attention. If you are performing a structured security review:

- The Python `core/` module is the primary audit target.
- `docs/PROTOCOL.md` is the authoritative specification for comparison against the implementation.
- `tests/` demonstrates the expected behavior of all key protocol properties.

Findings from structured audits may be disclosed on a mutually agreed timeline; we are happy to coordinate with auditing firms directly.

---

## 10. Roadmap

The Shadow roadmap is maintained in the repository `README.md`. The current status of each phase is:

| Phase | Description | Status |
|---|---|---|
| 0 | Double Ratchet | Complete (8/8 tests passing) |
| 1 | X3DH Handshake | Complete (4/4 tests passing) |
| 2 | Nostr Transport | Complete |
| 3 | Sealed Sender | Complete (6/6 integration tests passing) |
| 4 | Rust CLI + TUI | In progress |
| 5 | Mobile App (React Native) | In progress |
| 6 | Hardening + Public Audit | Planned |

Phase 6 hardening targets include:
- Independent cryptographic audit of the full protocol stack.
- Post-quantum migration: ML-KEM (CRYSTALS-Kyber, FIPS 203) for X3DH key encapsulation.
- Encrypted at-rest session storage (Argon2id key derivation).
- OPK replenishment signaling.
- Header encryption (Signal Double Ratchet §3.8).
- Message replay protection.
- Formal threat model review.

See `README.md` for the full task breakdown per phase.
