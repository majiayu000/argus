use super::TyposquatError;

pub(crate) const MAX_DATASET_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_AGGREGATE_DATASET_BYTES: usize = 16 * 1024 * 1024;
pub(crate) const MAX_ALIASES_PER_ENTRY: usize = 16;
pub(crate) const MAX_SOURCES_PER_FILE: usize = 64;
pub(crate) const MAX_KEYBOARD_KEYS: usize = 128;
pub(crate) const MAX_KEYBOARD_EDGES: usize = 512;
pub(crate) const MAX_KEYBOARD_DEGREE: usize = 16;
pub(crate) const MAX_CONFUSABLE_BYTES: usize = 4 * 1024 * 1024;
pub(crate) const MAX_CONFUSABLE_MAPPINGS: usize = 100_000;
pub(crate) const MAX_CONFUSABLE_TARGET_BYTES: usize = 64;
pub(crate) const MAX_SKELETON_BYTES: usize = 2_048;
pub(crate) const MAX_SKELETON_EXPANSION: usize = 8;

pub(crate) fn ensure_at_most(
    actual: usize,
    maximum: usize,
    label: &str,
) -> Result<(), TyposquatError> {
    if actual > maximum {
        Err(TyposquatError::ResourceLimit(format!(
            "{label} exceeds {maximum}"
        )))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_data_caps_accept_equality_and_reject_plus_one() {
        for (label, maximum) in [
            ("dataset bytes", MAX_DATASET_BYTES),
            ("aggregate dataset bytes", MAX_AGGREGATE_DATASET_BYTES),
            ("aliases", MAX_ALIASES_PER_ENTRY),
            ("sources", MAX_SOURCES_PER_FILE),
            ("keyboard keys", MAX_KEYBOARD_KEYS),
            ("keyboard edges", MAX_KEYBOARD_EDGES),
            ("keyboard degree", MAX_KEYBOARD_DEGREE),
            ("confusable bytes", MAX_CONFUSABLE_BYTES),
            ("confusable mappings", MAX_CONFUSABLE_MAPPINGS),
            ("confusable target bytes", MAX_CONFUSABLE_TARGET_BYTES),
            ("skeleton bytes", MAX_SKELETON_BYTES),
        ] {
            assert!(ensure_at_most(maximum, maximum, label).is_ok(), "{label}");
            assert!(
                ensure_at_most(maximum + 1, maximum, label).is_err(),
                "{label}"
            );
        }
    }
}
