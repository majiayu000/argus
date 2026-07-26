use anyhow::{bail, Result};
use std::cmp::Ordering;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct BigNat(String);

impl BigNat {
    pub(crate) fn parse(raw: &str) -> Result<Self> {
        if raw.is_empty() || !raw.bytes().all(|byte| byte.is_ascii_digit()) {
            bail!("version numeric component is not decimal");
        }
        Self::from_digit_values(raw.bytes().map(|byte| byte - b'0'))
    }

    pub(crate) fn from_digit_values(values: impl IntoIterator<Item = u8>) -> Result<Self> {
        let mut raw = String::new();
        for value in values {
            if value > 9 {
                bail!("version numeric component contains an invalid decimal value");
            }
            raw.push(char::from(b'0' + value));
        }
        if raw.is_empty() {
            bail!("version numeric component is empty");
        }
        let canonical = raw.trim_start_matches('0');
        Ok(Self(if canonical.is_empty() {
            "0".to_string()
        } else {
            canonical.to_string()
        }))
    }

    pub(crate) fn zero() -> Self {
        Self("0".to_string())
    }

    pub(crate) fn is_zero(&self) -> bool {
        self.0 == "0"
    }
}

impl Ord for BigNat {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for BigNat {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::BigNat;
    use std::cmp::Ordering;

    #[test]
    fn arbitrary_decimal_comparison_and_validation() {
        let zero = BigNat::zero();
        assert!(zero.is_zero());
        assert_eq!(BigNat::parse("0001").unwrap(), BigNat::parse("1").unwrap());
        let huge = BigNat::parse("100000000000000000000000000000000").unwrap();
        let lower = BigNat::parse("99999999999999999999999999999999").unwrap();
        assert_eq!(huge.partial_cmp(&lower), Some(Ordering::Greater));
        assert!(BigNat::parse("").is_err());
        assert!(BigNat::parse("12x").is_err());
        assert!(BigNat::from_digit_values([10]).is_err());
    }
}
