use crate::LockfileError;
use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use std::collections::BTreeSet;
use std::fmt;
use yaml_rust2::parser::{Event, MarkedEventReceiver, Parser};
use yaml_rust2::scanner::{Marker, TScalarStyle};
use yaml_rust2::{Yaml, YamlLoader};

pub const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
pub const MAX_RECORDS: usize = 100_000;
pub const MAX_NESTING_DEPTH: usize = 64;
pub const MAX_SCALAR_BYTES: usize = 1024 * 1024;
pub const MAX_SCALAR_COUNT: usize = 1_000_000;
pub const MAX_CANONICAL_OUTPUT_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy)]
pub struct BoundedInput<'a> {
    bytes: &'a [u8],
    text: &'a str,
    path_label: &'a str,
}

impl<'a> BoundedInput<'a> {
    pub fn new(bytes: &'a [u8], path_label: &'a str) -> Result<Self, LockfileError> {
        if bytes.len() > MAX_INPUT_BYTES {
            return Err(LockfileError::InputTooLarge {
                actual: bytes.len(),
                maximum: MAX_INPUT_BYTES,
            });
        }
        let text = std::str::from_utf8(bytes).map_err(|error| LockfileError::InvalidUtf8 {
            detail: error.to_string(),
        })?;
        Ok(Self {
            bytes,
            text,
            path_label,
        })
    }

    pub fn bytes(self) -> &'a [u8] {
        self.bytes
    }

    pub fn text(self) -> &'a str {
        self.text
    }

    pub fn path_label(self) -> &'a str {
        self.path_label
    }
}

pub fn ensure_record_count(count: usize) -> Result<(), LockfileError> {
    if count > MAX_RECORDS {
        return Err(LockfileError::RecordLimit {
            actual: count,
            maximum: MAX_RECORDS,
        });
    }
    Ok(())
}

pub fn ensure_canonical_output_size(size: usize) -> Result<(), LockfileError> {
    if size > MAX_CANONICAL_OUTPUT_BYTES {
        return Err(LockfileError::CanonicalOutputLimit {
            actual: size,
            maximum: MAX_CANONICAL_OUTPUT_BYTES,
        });
    }
    Ok(())
}

pub fn parse_json(input: &BoundedInput<'_>) -> Result<serde_json::Value, LockfileError> {
    let mut budget = ScalarBudget::default();
    let mut deserializer = serde_json::Deserializer::from_slice(input.bytes());
    JsonSeed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(&mut deserializer)
    .map_err(|error| json_error(error.to_string()))?;
    deserializer
        .end()
        .map_err(|error| json_error(error.to_string()))?;
    serde_json::from_slice(input.bytes()).map_err(|error| json_error(error.to_string()))
}

pub fn parse_toml(input: &BoundedInput<'_>) -> Result<toml::Value, LockfileError> {
    let value: toml::Value = toml::from_str(input.text()).map_err(|error| {
        let detail = error.to_string();
        if detail.contains("duplicate key") {
            LockfileError::DuplicateKey {
                syntax: "TOML",
                key: duplicate_key_from_message(&detail),
            }
        } else {
            LockfileError::Parse {
                syntax: "TOML",
                detail,
            }
        }
    })?;
    let mut budget = ScalarBudget::default();
    walk_toml(&value, 0, &mut budget)?;
    Ok(value)
}

pub fn parse_yaml(input: &BoundedInput<'_>) -> Result<Yaml, LockfileError> {
    let mut receiver = YamlGuard::default();
    let mut parser = Parser::new_from_str(input.text());
    parser
        .load(&mut receiver, true)
        .map_err(|error| LockfileError::Parse {
            syntax: "YAML",
            detail: error.to_string(),
        })?;
    receiver.finish()?;
    let documents =
        YamlLoader::load_from_str(input.text()).map_err(|error| LockfileError::Parse {
            syntax: "YAML",
            detail: format!("{error:?}"),
        })?;
    if documents.len() != 1 {
        return Err(LockfileError::Parse {
            syntax: "YAML",
            detail: format!("expected exactly one document, found {}", documents.len()),
        });
    }
    let document = documents
        .into_iter()
        .next()
        .ok_or_else(|| LockfileError::Parse {
            syntax: "YAML",
            detail: "document is empty".to_string(),
        })?;
    validate_yaml_string_keys(&document)?;
    Ok(document)
}

fn validate_yaml_string_keys(value: &Yaml) -> Result<(), LockfileError> {
    match value {
        Yaml::Hash(mapping) => {
            for (key, value) in mapping {
                if !matches!(key, Yaml::String(_)) {
                    return Err(LockfileError::UnsupportedYamlFeature {
                        feature: "non-string map key",
                    });
                }
                validate_yaml_string_keys(value)?;
            }
        }
        Yaml::Array(values) => {
            for value in values {
                validate_yaml_string_keys(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn json_error(detail: String) -> LockfileError {
    if let Some(key) = detail.strip_prefix("duplicate JSON map key `") {
        return LockfileError::DuplicateKey {
            syntax: "JSON",
            key: key.split('`').next().unwrap_or("<unknown>").to_string(),
        };
    }
    if detail.starts_with("nesting depth ") {
        return LockfileError::NestingLimit {
            actual: MAX_NESTING_DEPTH + 1,
            maximum: MAX_NESTING_DEPTH,
        };
    }
    if detail.starts_with("scalar count ") {
        return LockfileError::ScalarCountLimit {
            actual: MAX_SCALAR_COUNT + 1,
            maximum: MAX_SCALAR_COUNT,
        };
    }
    if detail.starts_with("scalar is ") {
        return LockfileError::ScalarTooLarge {
            actual: MAX_SCALAR_BYTES + 1,
            maximum: MAX_SCALAR_BYTES,
        };
    }
    LockfileError::Parse {
        syntax: "JSON",
        detail,
    }
}

fn duplicate_key_from_message(detail: &str) -> String {
    detail.split('`').nth(1).unwrap_or("<unknown>").to_string()
}

#[derive(Debug, Clone, Default)]
pub struct ScalarBudget {
    scalar_count: usize,
}

impl ScalarBudget {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn observed(&self) -> usize {
        self.scalar_count
    }

    pub fn observe(&mut self, value: &str) -> Result<(), LockfileError> {
        if value.len() > MAX_SCALAR_BYTES {
            return Err(LockfileError::ScalarTooLarge {
                actual: value.len(),
                maximum: MAX_SCALAR_BYTES,
            });
        }
        let actual = self
            .scalar_count
            .checked_add(1)
            .ok_or(LockfileError::ScalarCountLimit {
                actual: usize::MAX,
                maximum: MAX_SCALAR_COUNT,
            })?;
        if actual > MAX_SCALAR_COUNT {
            return Err(LockfileError::ScalarCountLimit {
                actual,
                maximum: MAX_SCALAR_COUNT,
            });
        }
        self.scalar_count = actual;
        Ok(())
    }

    fn enter(&self, depth: usize) -> Result<(), String> {
        if depth > MAX_NESTING_DEPTH {
            return Err(format!(
                "nesting depth {depth} exceeds maximum {MAX_NESTING_DEPTH}"
            ));
        }
        Ok(())
    }
}

struct JsonSeed<'a> {
    budget: &'a mut ScalarBudget,
    depth: usize,
}

impl<'de> DeserializeSeed<'de> for JsonSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<(), D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_any(JsonVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}

struct JsonVisitor<'a> {
    budget: &'a mut ScalarBudget,
    depth: usize,
}

impl<'de> Visitor<'de> for JsonVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a bounded JSON value")
    }

    fn visit_bool<E>(self, value: bool) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget
            .observe(if value { "true" } else { "false" })
            .map_err(E::custom)
    }

    fn visit_i64<E>(self, value: i64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.observe(&value.to_string()).map_err(E::custom)
    }

    fn visit_u64<E>(self, value: u64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.observe(&value.to_string()).map_err(E::custom)
    }

    fn visit_f64<E>(self, value: f64) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.observe(&value.to_string()).map_err(E::custom)
    }

    fn visit_str<E>(self, value: &str) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.observe(value).map_err(E::custom)
    }

    fn visit_string<E>(self, value: String) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.visit_str(&value)
    }

    fn visit_none<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.budget.observe("null").map_err(E::custom)
    }

    fn visit_unit<E>(self) -> Result<(), E>
    where
        E: serde::de::Error,
    {
        self.visit_none()
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<(), A::Error>
    where
        A: SeqAccess<'de>,
    {
        let depth = self.depth + 1;
        self.budget.enter(depth).map_err(A::Error::custom)?;
        while sequence
            .next_element_seed(JsonSeed {
                budget: self.budget,
                depth,
            })?
            .is_some()
        {}
        Ok(())
    }

    fn visit_map<A>(self, mut map: A) -> Result<(), A::Error>
    where
        A: MapAccess<'de>,
    {
        let depth = self.depth + 1;
        self.budget.enter(depth).map_err(A::Error::custom)?;
        let mut keys = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            self.budget.observe(&key).map_err(A::Error::custom)?;
            if !keys.insert(key.clone()) {
                return Err(A::Error::custom(format!("duplicate JSON map key `{key}`")));
            }
            map.next_value_seed(JsonSeed {
                budget: self.budget,
                depth,
            })?;
        }
        Ok(())
    }
}

fn walk_toml(
    value: &toml::Value,
    depth: usize,
    budget: &mut ScalarBudget,
) -> Result<(), LockfileError> {
    match value {
        toml::Value::Array(values) => {
            let next = depth + 1;
            budget.enter(next).map_err(budget_error)?;
            for value in values {
                walk_toml(value, next, budget)?;
            }
        }
        toml::Value::Table(values) => {
            let next = depth + 1;
            budget.enter(next).map_err(budget_error)?;
            for (key, value) in values {
                budget.observe(key)?;
                walk_toml(value, next, budget)?;
            }
        }
        toml::Value::String(value) => budget.observe(value)?,
        value => budget.observe(&value.to_string())?,
    }
    Ok(())
}

fn budget_error(detail: String) -> LockfileError {
    json_error(detail)
}

enum YamlFrame {
    Sequence,
    Mapping {
        expecting_key: bool,
        keys: BTreeSet<String>,
    },
}

#[derive(Default)]
struct YamlGuard {
    frames: Vec<YamlFrame>,
    budget: ScalarBudget,
    documents: usize,
    error: Option<LockfileError>,
}

impl YamlGuard {
    fn fail(&mut self, error: LockfileError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }

    fn node_position_is_map_key(&self) -> bool {
        matches!(
            self.frames.last(),
            Some(YamlFrame::Mapping {
                expecting_key: true,
                ..
            })
        )
    }

    fn complete_node(&mut self) {
        if let Some(YamlFrame::Mapping { expecting_key, .. }) = self.frames.last_mut() {
            *expecting_key = !*expecting_key;
        }
    }

    fn start_container(&mut self, frame: YamlFrame, anchor: usize, tagged: bool) {
        if anchor != 0 {
            self.fail(LockfileError::UnsupportedYamlFeature { feature: "anchor" });
        }
        if tagged {
            self.fail(LockfileError::UnsupportedYamlFeature { feature: "tag" });
        }
        if self.node_position_is_map_key() {
            self.fail(LockfileError::UnsupportedYamlFeature {
                feature: "non-string map key",
            });
        }
        let depth = self.frames.len() + 1;
        if let Err(detail) = self.budget.enter(depth) {
            self.fail(budget_error(detail));
        }
        self.frames.push(frame);
    }

    fn scalar(&mut self, value: String, style: TScalarStyle, anchor: usize, tagged: bool) {
        if anchor != 0 {
            self.fail(LockfileError::UnsupportedYamlFeature { feature: "anchor" });
        }
        if tagged {
            self.fail(LockfileError::UnsupportedYamlFeature { feature: "tag" });
        }
        if let Err(error) = self.budget.observe(&value) {
            self.fail(error);
        }
        if let Some(YamlFrame::Mapping {
            expecting_key: true,
            keys,
        }) = self.frames.last_mut()
        {
            if style == TScalarStyle::Plain && is_non_string_yaml_scalar(&value) {
                self.fail(LockfileError::UnsupportedYamlFeature {
                    feature: "non-string map key",
                });
                return;
            }
            if value == "<<" {
                self.fail(LockfileError::UnsupportedYamlFeature {
                    feature: "merge key",
                });
                return;
            }
            if !keys.insert(value.clone()) {
                self.fail(LockfileError::DuplicateKey {
                    syntax: "YAML",
                    key: value,
                });
                return;
            }
        }
        self.complete_node();
    }

    fn end_container(&mut self) {
        if self.frames.pop().is_none() {
            self.fail(LockfileError::Parse {
                syntax: "YAML",
                detail: "container end without start".to_string(),
            });
            return;
        }
        self.complete_node();
    }

    fn finish(self) -> Result<(), LockfileError> {
        if let Some(error) = self.error {
            return Err(error);
        }
        if !self.frames.is_empty() {
            return Err(LockfileError::Parse {
                syntax: "YAML",
                detail: "unclosed container".to_string(),
            });
        }
        if self.documents != 1 {
            return Err(LockfileError::Parse {
                syntax: "YAML",
                detail: format!("expected exactly one document, found {}", self.documents),
            });
        }
        Ok(())
    }
}

impl MarkedEventReceiver for YamlGuard {
    fn on_event(&mut self, event: Event, _mark: Marker) {
        match event {
            Event::DocumentStart => self.documents += 1,
            Event::Alias(_) => {
                self.fail(LockfileError::UnsupportedYamlFeature { feature: "alias" })
            }
            Event::Scalar(value, style, anchor, tag) => {
                self.scalar(value, style, anchor, tag.is_some())
            }
            Event::SequenceStart(anchor, tag) => {
                self.start_container(YamlFrame::Sequence, anchor, tag.is_some())
            }
            Event::MappingStart(anchor, tag) => self.start_container(
                YamlFrame::Mapping {
                    expecting_key: true,
                    keys: BTreeSet::new(),
                },
                anchor,
                tag.is_some(),
            ),
            Event::SequenceEnd | Event::MappingEnd => self.end_container(),
            Event::Nothing | Event::StreamStart | Event::StreamEnd | Event::DocumentEnd => {}
        }
    }
}

fn is_non_string_yaml_scalar(value: &str) -> bool {
    matches!(
        value,
        "" | "~"
            | "null"
            | "Null"
            | "NULL"
            | "true"
            | "True"
            | "TRUE"
            | "false"
            | "False"
            | "FALSE"
            | ".inf"
            | ".Inf"
            | ".INF"
            | "-.inf"
            | "-.Inf"
            | "-.INF"
            | "+.inf"
            | "+.Inf"
            | "+.INF"
            | ".nan"
            | ".NaN"
            | ".NAN"
    ) || value.parse::<i64>().is_ok()
        || value.parse::<f64>().is_ok()
}
