// Implemented by the GH90 intelligence owner.
use anyhow::{bail, Result};

pub(crate) const SUPPORTED_SCHEMA_VERSIONS: &[&str] = &[
    "1.0.0", "1.1.0", "1.2.0", "1.3.0", "1.4.0", "1.5.0", "1.6.0", "1.7.0", "1.7.1", "1.7.2",
    "1.7.3", "1.7.4",
];

#[derive(Clone, Copy)]
pub(crate) enum StringRule {
    Any,
    Frozen(&'static [&'static str]),
}

#[derive(Clone, Copy)]
pub(crate) struct FieldCaps {
    pub top_database_specific: bool,
    pub credits_and_top_severity: bool,
    pub last_affected_and_range_database: bool,
    pub affected_severity_and_credit_type: bool,
    pub upstream: bool,
    pub nullable_core_collections: bool,
    pub required_affected_range_types: &'static [&'static str],
}

pub(crate) struct SchemaProfile {
    pub version: &'static str,
    pub fields: FieldCaps,
    pub reference_types: &'static [&'static str],
    pub severity_types: &'static [&'static str],
    id_rule: StringRule,
    ecosystem_rule: StringRule,
}

impl SchemaProfile {
    pub(crate) fn validate_id(&self, value: &str) -> Result<()> {
        match self.id_rule {
            StringRule::Any => Ok(()),
            StringRule::Frozen(prefixes) => {
                if prefixes.iter().any(|prefix| {
                    value.starts_with(prefix)
                        && value.as_bytes().get(prefix.len()).copied() == Some(b'-')
                }) {
                    Ok(())
                } else {
                    bail!(
                        "advisory id `{value}` is not defined by OSV schema {}",
                        self.version
                    )
                }
            }
        }
    }

    pub(crate) fn validate_ecosystem(&self, value: &str) -> Result<()> {
        if matches!(self.ecosystem_rule, StringRule::Any) {
            return Ok(());
        }
        let (base, suffix) = value
            .split_once(':')
            .map_or((value, None), |(base, suffix)| (base, Some(suffix)));
        if suffix.is_some_and(str::is_empty) {
            bail!("OSV ecosystem suffix is empty");
        }
        match self.ecosystem_rule {
            StringRule::Any => unreachable!("historical string rule returned above"),
            StringRule::Frozen(ecosystems) if ecosystems.contains(&base) || base == "GIT" => Ok(()),
            StringRule::Frozen(_) => bail!(
                "OSV ecosystem `{value}` is not defined by schema {}",
                self.version
            ),
        }
    }
}

const REFERENCE_1_0: &[&str] = &[
    "ADVISORY", "ARTICLE", "REPORT", "FIX", "GIT", "PACKAGE", "WEB",
];
const REFERENCE_1_3: &[&str] = &[
    "ADVISORY", "ARTICLE", "REPORT", "FIX", "GIT", "PACKAGE", "EVIDENCE", "WEB",
];
const REFERENCE_1_5: &[&str] = &[
    "ADVISORY",
    "ARTICLE",
    "DETECTION",
    "DISCUSSION",
    "REPORT",
    "FIX",
    "INTRODUCED",
    "GIT",
    "PACKAGE",
    "EVIDENCE",
    "WEB",
];
const SEVERITY_NONE: &[&str] = &[];
const SEVERITY_V3: &[&str] = &["CVSS_V3"];
const SEVERITY_V2_V3: &[&str] = &["CVSS_V2", "CVSS_V3"];
const SEVERITY_1_7: &[&str] = &["CVSS_V2", "CVSS_V3", "CVSS_V4", "Ubuntu"];

const ECOSYSTEM_1_7_0: &[&str] = &[
    "AlmaLinux",
    "Alpine",
    "Android",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "npm",
    "NuGet",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "Ubuntu",
    "Wolfi",
];
const ECOSYSTEM_1_7_2: &[&str] = &[
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "npm",
    "NuGet",
    "openEuler",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "Ubuntu",
    "Wolfi",
];
const ECOSYSTEM_1_7_3: &[&str] = &[
    "Echo",
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "npm",
    "NuGet",
    "openEuler",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "Ubuntu",
    "Wolfi",
];
const ECOSYSTEM_1_7_4: &[&str] = &[
    "AlmaLinux",
    "Alpaquita",
    "Alpine",
    "Android",
    "BellSoft Hardened Containers",
    "Bioconductor",
    "Bitnami",
    "Chainguard",
    "ConanCenter",
    "CRAN",
    "crates.io",
    "Debian",
    "Echo",
    "GHC",
    "GitHub Actions",
    "Go",
    "Hackage",
    "Hex",
    "Julia",
    "Kubernetes",
    "Linux",
    "Mageia",
    "Maven",
    "MinimOS",
    "npm",
    "NuGet",
    "openEuler",
    "openSUSE",
    "OSS-Fuzz",
    "Packagist",
    "Photon OS",
    "Pub",
    "PyPI",
    "Red Hat",
    "Rocky Linux",
    "RubyGems",
    "SUSE",
    "SwiftURL",
    "Ubuntu",
    "VSCode",
    "Wolfi",
];

const PREFIX_1_7_0: &[&str] = &[
    "ASB-A",
    "PUB-A",
    "ALSA",
    "ALBA",
    "ALEA",
    "BIT",
    "CGA",
    "CURL",
    "CVE",
    "DSA",
    "DLA",
    "ELA",
    "DTSA",
    "GHSA",
    "GO",
    "GSD",
    "HSEC",
    "KUBE",
    "LBSEC",
    "MAL",
    "MGASA",
    "OSV",
    "openSUSE-SU",
    "PHSA",
    "PSF",
    "PYSEC",
    "RHBA",
    "RHEA",
    "RHSA",
    "RLSA",
    "RXSA",
    "RSEC",
    "RUSTSEC",
    "SUSE-SU",
    "SUSE-RU",
    "SUSE-FU",
    "SUSE-OU",
    "UBUNTU",
    "USN",
    "V8",
];
const PREFIX_1_7_2: &[&str] = &[
    "BELL",
    "LSN",
    "MINI",
    "OESA",
    "ASB-A",
    "PUB-A",
    "ALSA",
    "ALBA",
    "ALEA",
    "BIT",
    "CGA",
    "CURL",
    "CVE",
    "DSA",
    "DLA",
    "ELA",
    "DTSA",
    "GHSA",
    "GO",
    "GSD",
    "HSEC",
    "KUBE",
    "LBSEC",
    "MAL",
    "MGASA",
    "OSV",
    "openSUSE-SU",
    "PHSA",
    "PSF",
    "PYSEC",
    "RHBA",
    "RHEA",
    "RHSA",
    "RLSA",
    "RXSA",
    "RSEC",
    "RUSTSEC",
    "SUSE-SU",
    "SUSE-RU",
    "SUSE-FU",
    "SUSE-OU",
    "UBUNTU",
    "USN",
    "V8",
];
const PREFIX_1_7_4: &[&str] = &[
    "ALPINE",
    "DEBIAN",
    "ECHO",
    "EEF",
    "JLSEC",
    "BELL",
    "LSN",
    "MINI",
    "OESA",
    "ASB-A",
    "PUB-A",
    "ALSA",
    "ALBA",
    "ALEA",
    "BIT",
    "CGA",
    "CURL",
    "CVE",
    "DSA",
    "DLA",
    "ELA",
    "DTSA",
    "GHSA",
    "GO",
    "GSD",
    "HSEC",
    "KUBE",
    "LBSEC",
    "MAL",
    "MGASA",
    "OSV",
    "openSUSE-SU",
    "PHSA",
    "PSF",
    "PYSEC",
    "RHBA",
    "RHEA",
    "RHSA",
    "RLSA",
    "RXSA",
    "RSEC",
    "RUSTSEC",
    "SUSE-SU",
    "SUSE-RU",
    "SUSE-FU",
    "SUSE-OU",
    "UBUNTU",
    "USN",
    "V8",
];

const FIELDS_1_0: FieldCaps = FieldCaps {
    top_database_specific: false,
    credits_and_top_severity: false,
    last_affected_and_range_database: false,
    affected_severity_and_credit_type: false,
    upstream: false,
    nullable_core_collections: false,
    required_affected_range_types: &["SEMVER"],
};
const FIELDS_1_1: FieldCaps = FieldCaps {
    top_database_specific: true,
    required_affected_range_types: &["SEMVER", "ECOSYSTEM"],
    ..FIELDS_1_0
};
const FIELDS_1_2: FieldCaps = FieldCaps {
    credits_and_top_severity: true,
    ..FIELDS_1_1
};
const FIELDS_1_3: FieldCaps = FieldCaps {
    last_affected_and_range_database: true,
    ..FIELDS_1_2
};
const FIELDS_1_4: FieldCaps = FieldCaps {
    affected_severity_and_credit_type: true,
    nullable_core_collections: true,
    required_affected_range_types: &[],
    ..FIELDS_1_3
};
const FIELDS_1_7: FieldCaps = FieldCaps {
    upstream: true,
    ..FIELDS_1_4
};

pub(crate) static PROFILES: &[SchemaProfile] = &[
    SchemaProfile {
        version: "1.0.0",
        fields: FIELDS_1_0,
        reference_types: REFERENCE_1_0,
        severity_types: SEVERITY_NONE,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.1.0",
        fields: FIELDS_1_1,
        reference_types: REFERENCE_1_0,
        severity_types: SEVERITY_NONE,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.2.0",
        fields: FIELDS_1_2,
        reference_types: REFERENCE_1_0,
        severity_types: SEVERITY_V3,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.3.0",
        fields: FIELDS_1_3,
        reference_types: REFERENCE_1_3,
        severity_types: SEVERITY_V3,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.4.0",
        fields: FIELDS_1_4,
        reference_types: REFERENCE_1_3,
        severity_types: SEVERITY_V2_V3,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.5.0",
        fields: FIELDS_1_4,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_V2_V3,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.6.0",
        fields: FIELDS_1_4,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_V2_V3,
        id_rule: StringRule::Any,
        ecosystem_rule: StringRule::Any,
    },
    SchemaProfile {
        version: "1.7.0",
        fields: FIELDS_1_7,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_1_7,
        id_rule: StringRule::Frozen(PREFIX_1_7_0),
        ecosystem_rule: StringRule::Frozen(ECOSYSTEM_1_7_0),
    },
    SchemaProfile {
        version: "1.7.1",
        fields: FIELDS_1_7,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_1_7,
        id_rule: StringRule::Frozen(PREFIX_1_7_0),
        ecosystem_rule: StringRule::Frozen(ECOSYSTEM_1_7_0),
    },
    SchemaProfile {
        version: "1.7.2",
        fields: FIELDS_1_7,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_1_7,
        id_rule: StringRule::Frozen(PREFIX_1_7_2),
        ecosystem_rule: StringRule::Frozen(ECOSYSTEM_1_7_2),
    },
    SchemaProfile {
        version: "1.7.3",
        fields: FIELDS_1_7,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_1_7,
        id_rule: StringRule::Frozen(PREFIX_1_7_2),
        ecosystem_rule: StringRule::Frozen(ECOSYSTEM_1_7_3),
    },
    SchemaProfile {
        version: "1.7.4",
        fields: FIELDS_1_7,
        reference_types: REFERENCE_1_5,
        severity_types: SEVERITY_1_7,
        id_rule: StringRule::Frozen(PREFIX_1_7_4),
        ecosystem_rule: StringRule::Frozen(ECOSYSTEM_1_7_4),
    },
];

pub(crate) fn profile(version: &str) -> Option<&'static SchemaProfile> {
    PROFILES.iter().find(|profile| profile.version == version)
}
