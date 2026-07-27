//! Offline, versioned package-name reputation data and bounded typo matching.
//!
//! Data is embedded in the binary and validated once before first use. Scans
//! never download reputation data and never fall back to the legacy arrays.

mod data;
mod matcher;
mod normalize;
mod strict_json;

use argus_core::Ecosystem;
use std::fmt;

pub use data::{
    asset_audit, dataset_audit, validate_embedded_assets, AssetAudit, DatasetAudit,
    TyposquatDataAudit,
};
pub use matcher::{match_typosquat, match_typosquat_with_options};
pub use normalize::canonicalize_typosquat_identity;

/// Maximum accepted UTF-8 bytes in one package identity.
pub const MAX_CANDIDATE_BYTES: usize = 512;
/// Maximum accepted Unicode scalar values in one package identity.
pub const MAX_CANDIDATE_SCALARS: usize = 256;
/// Maximum targets examined for one identity.
pub const MAX_MATCH_COMPARISONS: usize = 10_000;
/// Maximum edit distance supported by the bounded matcher.
pub const MAX_EDIT_DISTANCE: u8 = 2;
/// Distance two is only meaningful for targets at least this long.
pub const MIN_LENGTH_FOR_DISTANCE_TWO: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TyposquatMatchOptions {
    pub max_edit_distance: u8,
    pub min_length_for_distance_two: usize,
    pub edit_distance_enabled: bool,
    pub keyboard_enabled: bool,
    pub unicode_confusables_enabled: bool,
}

impl Default for TyposquatMatchOptions {
    fn default() -> Self {
        Self {
            max_edit_distance: 1,
            min_length_for_distance_two: MIN_LENGTH_FOR_DISTANCE_TWO,
            edit_distance_enabled: true,
            keyboard_enabled: true,
            unicode_confusables_enabled: true,
        }
    }
}

impl TyposquatMatchOptions {
    pub fn validate(self) -> Result<Self, TyposquatError> {
        if self.max_edit_distance > MAX_EDIT_DISTANCE {
            return Err(TyposquatError::Configuration(format!(
                "max edit distance {} exceeds {MAX_EDIT_DISTANCE}",
                self.max_edit_distance
            )));
        }
        if self.min_length_for_distance_two < MIN_LENGTH_FOR_DISTANCE_TWO {
            return Err(TyposquatError::Configuration(format!(
                "distance-two minimum length {} is below {MIN_LENGTH_FOR_DISTANCE_TWO}",
                self.min_length_for_distance_two
            )));
        }
        Ok(self)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum TyposquatSignal {
    EditDistance { distance: u8 },
    Transposition,
    KeyboardAdjacent,
    UnicodeConfusable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TyposquatMatch {
    pub ecosystem: Ecosystem,
    pub candidate: String,
    pub canonical_candidate: String,
    pub target: String,
    pub canonical_target: String,
    pub signals: Vec<TyposquatSignal>,
    pub dataset_id: String,
    pub dataset_version: u32,
    pub dataset_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TyposquatError {
    InvalidIdentity(String),
    InvalidEmbeddedData(String),
    ResourceLimit(String),
    Configuration(String),
}

impl fmt::Display for TyposquatError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidIdentity(message) => {
                write!(formatter, "invalid package identity: {message}")
            }
            Self::InvalidEmbeddedData(message) => {
                write!(formatter, "invalid embedded typosquat data: {message}")
            }
            Self::ResourceLimit(message) => {
                write!(formatter, "typosquat resource limit: {message}")
            }
            Self::Configuration(message) => {
                write!(formatter, "invalid typosquat configuration: {message}")
            }
        }
    }
}

impl std::error::Error for TyposquatError {}
