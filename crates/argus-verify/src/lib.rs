//! Sigstore signature verification for argus.
//!
//! The crate exposes two verification layers (see
//! `docs/design/sigstore-verification.md`):
//! - standalone DSSE envelope signature verification against the leaf
//!   certificate embedded in a bundle's verification material; and
//! - full Fulcio certificate-chain, SCT, Rekor transparency-log, artifact, and
//!   caller-supplied OIDC identity-policy verification.
//!
//! The standalone DSSE result proves only that the holder of the leaf
//! certificate's private key signed the payload. It is NOT a trust decision:
//! callers that need a trust decision must use [`verify_bundle_full`].

mod dsse;
mod sigstore;

pub use dsse::{verify_bundle_dsse, verify_dsse_signature, DsseVerdict};
pub use sigstore::{verify_bundle_full, IdentityAllowlist, SigstoreVerdict};
