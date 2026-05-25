//! Per-artifact scan result shape.
//!
//! Returned by ecosystem-specific scan helpers (`scan_sdist_dir`,
//! `scan_wheel_zip`, `scan_extracted_crate`, …) so the caller can
//! decorate it with name + version metadata before producing the final
//! [`crate::ScanReport`].

use crate::Finding;

pub struct ArtifactScan {
    pub findings: Vec<Finding>,
    pub name: Option<String>,
    pub version: Option<String>,
}
