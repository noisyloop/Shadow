# Contributing to Shadow

Shadow is an end-to-end encrypted messaging system built on the Double Ratchet
algorithm, X3DH key agreement, Sealed Sender, and Nostr routing. This document
covers everything you need to contribute code, tests, or documentation.

---

## Table of Contents

1. [Project Philosophy](#1-project-philosophy)
2. [Repository Structure](#2-repository-structure)
3. [Development Setup](#3-development-setup)
4. [Running the Test Suites](#4-running-the-test-suites)
5. [Crypto Contribution Guidelines](#5-crypto-contribution-guidelines)
6. [Code Style](#6-code-style)
7. [Pull Request Requirements](#7-pull-request-requirements)
8. [Security Vulnerability Disclosure](#8-security-vulnerability-disclosure)

---

## 1. Project Philosophy

**Security over convenience.** Every design decision defaults to the more
secure option. Convenience features may be added later only if they do not
compromise the threat model documented in `docs/THREAT_MODEL.md`.

**Minimal dependencies.** Each dependency is a potential supply-chain attack
surface. Prefer standard library primitives and well-audited, widely-deployed
cryptographic libraries (libsodium, BoringSSL, @noble, dalek-cryptography)
over niche alternatives.

**No home-grown cryptography.** All cryptographic primitives (AES-GCM, HKDF,
HMAC-SHA256, X25519, ed25519) are delegated to audited libraries. The
_algorithms_ (Double Ratchet, X3DH, Sealed Sender) are Shadow's own
composition of those primitives, verified against published test vectors where
available.

**Deterministic, auditable state transitions.** The ratchet state machine must
be entirely reproducible from its serialized state. No hidden mutable global
state.

**Tests are not optional.** Every change to `core/`, `transport/`, `cli/src/`,
or `mobile/src/crypto/` must include or update tests. PRs that delete test
coverage will not be merged.

---

## 2. Repository Structure

```
Shadow/
├── core/                   # Python reference implementation (Phases 0–3)
│   ├── ratchet.py          # Double Ratchet (RFC/Signal spec)
│   ├── identity.py         # Device identity, SPK, OPK, prekey bundle
│   └── x3dh.py             # X3DH send/receive, InitialMessage wire format
├── transport/              # Python networking layer
│   ├── nostr.py            # BIP340 Schnorr, NostrEvent, RelayClient, LocalRelay
│   └── sealed_sender.py    # ECIES envelope, SenderCertificate, seal/unseal
├── tests/                  # Pytest test suites
│   ├── test_ratchet.py     # 8 Double Ratchet tests
│   ├── test_x3dh.py        # 4 X3DH tests
│   └── test_integration.py # 6 end-to-end integration tests
├── cli/                    # Rust CLI/TUI (Phase 4)
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs
│       ├── commands/       # init, add, key, send, recv
│       ├── crypto/         # ratchet.rs, identity.rs, x3dh.rs
│       ├── transport/      # nostr.rs
│       ├── tui/            # app.rs, ui.rs
│       └── store.rs        # ~/.shadow/ persistence
├── mobile/                 # React Native / Expo app (Phase 5)
│   ├── App.tsx
│   ├── package.json
│   └── src/
│       ├── crypto/         # identity.ts, ratchet.ts, x3dh.ts
│       ├── store/          # keys.ts, messages.ts, contacts.ts
│       ├── screens/        # HomeScreen, ChatScreen, AddContactScreen, KeyScreen
│       ├── components/     # MessageBubble, QRDisplay
│       └── navigation/     # index.tsx
└── docs/
    ├── PROTOCOL.md         # Full cryptographic protocol specification
    └── THREAT_MODEL.md     # Threat actors, trust assumptions, known weaknesses
```

---

## 3. Development Setup

### Prerequisites

| Tool       | Minimum version | Purpose                        |
|------------|-----------------|--------------------------------|
| Python     | 3.11            | Reference implementation, tests|
| Rust       | 1.70 (stable)   | CLI/TUI                        |
| Node.js    | 18 LTS          | React Native / Expo mobile     |
| Expo CLI   | 0.18+           | Mobile build tooling           |

### Python environment

```bash
# From repo root
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install cryptography pytest websockets
```

No `requirements.txt` yet — see issue #TBD. Until then use the command above.

### Rust

```bash
cd cli
cargo build                        # debug build
cargo build --release              # optimised build
cargo run -- --help                # verify CLI is wired
```

The first build downloads all crates. Subsequent builds are incremental.

### React Native / Expo

```bash
cd mobile
npm install
npx expo start                     # Metro bundler + QR code for device
npx expo run:ios                   # Requires Xcode on macOS
npx expo run:android               # Requires Android SDK
```

---

## 4. Running the Test Suites

### Python tests (all three suites must pass before merging)

```bash
# From repo root, with venv activated
python -m pytest tests/ -v
```

Expected output:

```
tests/test_ratchet.py ........   [8 passed]
tests/test_x3dh.py ....          [4 passed]
tests/test_integration.py ......  [6 passed]
```

Individual suites:

```bash
python -m pytest tests/test_ratchet.py -v       # Double Ratchet
python -m pytest tests/test_x3dh.py -v          # X3DH
python -m pytest tests/test_integration.py -v   # Sealed Sender + Nostr
```

### Rust tests

```bash
cd cli
cargo test                         # all unit tests
cargo test -- --nocapture          # show println! output
```

### Mobile (TypeScript)

```bash
cd mobile
npx tsc --noEmit                   # type-check without emitting
```

Jest integration is planned (issue #TBD). Until then, TypeScript type-checking
is the gate.

---

## 5. Crypto Contribution Guidelines

**Read the spec first.** `docs/PROTOCOL.md` defines the authoritative wire
format and KDF constants. Any change that alters the wire format or KDF
derivation requires a protocol version bump and must be discussed in an issue
before implementation.

### What requires extra review

- Any change to KDF constants (`INFO` strings, HMAC constants `0x01`/`0x02`)
- Any change to AEAD construction (nonce derivation, AD binding)
- Any change to the ratchet state machine (skip-message-key limits, DH ratchet
  trigger conditions)
- Any change to the X3DH DH output ordering or HKDF info string
- Any change to the Sealed Sender ECIES construction

### What is off-limits without a protocol version bump

- Changing the wire format of `Header`, `InitialMessage`, or the sealed sender
  envelope
- Changing the `shadow-session-v1:` associated data prefix
- Changing error-correction level from `M` in QR codes (affects interoperability)

### Key hygiene

- Never log raw key material (not even in debug builds). Use truncated hex
  prefixes (first 8 bytes) for debugging.
- Keys in Python must be stored as raw `bytes`, never as library key objects
  (they can't be deepcopied or serialized safely).
- Keys in Rust use `[u8; 32]` arrays. Secrets should use `zeroize` where the
  type supports it.
- Keys in TypeScript are hex-encoded strings for store compatibility.

### Adding a new cryptographic primitive

1. Open an issue describing the primitive, the library you intend to use, and
   why the current primitives are insufficient.
2. Link to the library's audit reports and maintenance record.
3. Implement the primitive in isolation with its own unit tests.
4. Update `docs/PROTOCOL.md` with the new algorithm section.
5. Update `docs/THREAT_MODEL.md` if the threat surface changes.

---

## 6. Code Style

### Python

- Format with `black` (line length 88).
- Type-annotate all public functions.
- Use `snake_case` for everything.
- Docstrings for all public functions (one-line summary + parameter description
  for anything non-obvious).

### Rust

- Format with `cargo fmt`.
- Lint with `cargo clippy -- -D warnings` (no warnings allowed).
- Use `snake_case` for functions/variables, `CamelCase` for types.
- Document all `pub` items with `///` doc comments.

### TypeScript / React Native

- Format with Prettier (default config).
- `strict: true` TypeScript — no `any`, no type assertions without a comment
  explaining why.
- React components: `memo()` for all pure display components.
- Prefer `useCallback`/`useMemo` for functions and objects passed as props.

---

## 7. Pull Request Requirements

1. **Branch naming**: `feature/<short-description>`, `fix/<issue-number>`,
   `docs/<section>`.
2. **All tests pass**: Python pytest (18/18), Rust `cargo test`, TypeScript
   `tsc --noEmit`.
3. **No new lint warnings**: `cargo clippy` clean for Rust changes.
4. **Changelog entry**: add a line to `CHANGELOG.md` under `[Unreleased]`
   (create the file if it doesn't exist).
5. **Crypto changes**: require approval from at least one maintainer with
   cryptography background before merge, regardless of test coverage.
6. **Description**: must include _what_ changed, _why_, and _how to test_.

### Commit messages

Use conventional commits:

```
feat(ratchet): add configurable skipped-key limit
fix(x3dh): reject bundles with expired SPK signatures
docs(threat-model): add post-quantum threat section
test(integration): verify sealed sender with no OPK
```

---

## 8. Security Vulnerability Disclosure

**Do not open a public GitHub issue for security vulnerabilities.**

### Responsible disclosure process

1. Email `security@shadow-project.example` (placeholder — replace with real
   address before going public) with subject `[SECURITY] <brief description>`.
2. Include:
   - Affected component(s) and version/commit hash
   - Description of the vulnerability and its impact
   - Steps to reproduce or proof-of-concept code
   - Your preferred contact information
3. You will receive an acknowledgement within **48 hours**.
4. We target a **90-day** fix timeline from initial report. We will keep you
   updated on progress and coordinate disclosure timing with you.
5. If you do not hear back within 48 hours, follow up via GitHub Discussions
   (without revealing the vulnerability details).

### Scope

Issues we consider in scope:

- Cryptographic protocol weaknesses (ratchet state, X3DH, Sealed Sender)
- Key material leakage (logs, crash dumps, insecure storage)
- Authentication bypass (forged sender certificates, bad SPK verification)
- Relay-side deanonymisation beyond the documented threat model

Issues out of scope:

- Denial of service against a relay you operate
- Social engineering attacks
- Issues in third-party dependencies (report to the upstream maintainer)

### Recognition

With your permission, we will credit you in the release notes for the patched
version.
