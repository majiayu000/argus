# sigstore-verify

Sigstore signature verification for [sigstore-rust](https://github.com/sigstore/sigstore-rust).

## Argus vendoring record

This directory is the crates.io `sigstore-verify` 0.11.0 source package,
patched narrowly for npm Sigstore bundle v0.2 compatibility.

- Upstream tag: `sigstore-verify-v0.11.0`
- Upstream commit: `ef17cacdbd357befea4c1c768ef02ed9bf52672c`
- Crates.io package SHA-256:
  `558f71aad0e1c5925d29ae2024f55f0f8898a7ad450c93668f99086624c421e0`
- License: Apache-2.0, matching the package metadata and upstream `LICENSE`

Argus changes only the candidate timestamp allowlist, byte-derived SHA-512
in-toto subject binding, committed `intoto/0.0.2` Rekor body consistency,
and a mechanical helper extraction needed to keep files below the repository
size limit. None of the SET, checkpoint/proof, Fulcio chain/time/EKU, SCT,
DSSE signature, Rekor consistency, or identity checks are skipped.

The crates.io package's 1,264-line `tests/verification_tests.rs` is omitted:
it exceeds Argus's 800-line hard limit and imports sibling
`sigstore-bundle/tests/fixtures` files that the published crate does not
contain. Argus's real npm fixture matrix replaces that non-runnable test entry.

Remove this path patch only when a later upstream release passes Argus's real
npm positive fixture and the complete fail-closed mutation matrix.

## Overview

This crate provides high-level APIs for verifying Sigstore signatures. It handles the complete verification flow: bundle parsing, certificate chain validation, signature verification, transparency log verification, and identity policy enforcement.

## Features

- **Bundle verification**: Verify standard Sigstore bundles
- **Certificate validation**: X.509 chain validation against Fulcio CA
- **Transparency log verification**: Checkpoint signatures, inclusion proofs, SETs
- **Timestamp verification**: RFC 3161 timestamp validation
- **Identity policies**: Verify signer identity claims (issuer, subject, etc.)

## Verification Steps

1. Parse and validate bundle structure
2. Verify certificate chain against trusted root
3. Verify signature over artifact
4. Verify transparency log entry (checkpoint, inclusion proof, or SET)
5. Verify timestamps if present
6. Check identity against policy (optional)

## Usage

```rust
use sigstore_verify::{verify, Verifier, VerificationPolicy};
use sigstore_trust_root::{TrustedRoot, TufConfig};
use sigstore_types::{Artifact, Bundle, Sha256Hash};

let bundle: Bundle = serde_json::from_str(bundle_json)?;
let policy = VerificationPolicy::default();

// Actively choose the Sigstore instance and fetch its root through TUF.
let root = TrustedRoot::from_tuf(TufConfig::production()).await?;

// Verify with raw artifact bytes
let artifact_bytes = b"hello world";
let result = verify(artifact_bytes.as_slice(), &bundle, &policy, &root)?;

// Or verify with pre-computed SHA-256 digest (useful for large files)
let digest = Sha256Hash::from_hex("b94d27b9...")?;
let result = verify(digest, &bundle, &policy, &root)?;

// Using the Verifier struct directly
let verifier = Verifier::new(&root);
let result = verifier.verify(artifact_bytes.as_slice(), &bundle, &policy)?;
```

For GitHub artifact attestations, choose GitHub's Sigstore instance explicitly
and use the GitHub verification profile:

```rust
use sigstore_trust_root::{SigstoreInstance, TrustedRoot};
use sigstore_verify::{verify, VerificationPolicy};
use sigstore_types::{Bundle, Sha256Hash};

let bundle: Bundle = serde_json::from_str(bundle_json)?;
let artifact_digest = Sha256Hash::from_hex("...")?;

// Fetch GitHub's trusted root over TUF (now supported via the `sigstore-tuf`
// client), or use the embedded copy below for an offline path.
// let root = TrustedRoot::from_tuf(sigstore_trust_root::TufConfig::github()).await?;
let root = TrustedRoot::from_embedded(SigstoreInstance::GitHub)?;
let policy = VerificationPolicy::default().skip_tlog().skip_sct();

let result = verify(artifact_digest, &bundle, &policy, &root)?;
```

## Verification Policies

```rust
use sigstore_verify::VerificationPolicy;

// Default policy (verify tlog, timestamps, and certificate chain)
let policy = VerificationPolicy::default();

// Require specific identity and issuer
let policy = VerificationPolicy::default()
    .require_identity("user@example.com")
    .require_issuer("https://accounts.google.com");

// Skip certain verifications (for testing only)
let policy = VerificationPolicy::default()
    .skip_tlog()
    .skip_certificate_chain();
```

## Related Crates

- [`sigstore-sign`](../sigstore-sign) - Create signatures to verify with this crate

## License

Apache-2.0
