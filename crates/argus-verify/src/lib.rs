//! Sigstore signature verification for argus.
//!
//! Milestone progression (see docs/design/sigstore-verification.md):
//! - **Day 1 (this module set)**: DSSE envelope signature verification against
//!   the leaf certificate embedded in a bundle's verification material.
//! - **Later**: Fulcio certificate-chain verification, Rekor transparency-log
//!   inclusion proofs, and the OIDC builder-identity allowlist.
//!
//! Verifying a DSSE signature here proves only that the holder of the leaf
//! certificate's private key signed the payload. It is NOT a trust decision:
//! the certificate chain and OIDC identity must still be checked before an
//! attestation can be treated as trustworthy.

mod dsse;

pub use dsse::{verify_bundle_dsse, verify_dsse_signature, DsseVerdict};
