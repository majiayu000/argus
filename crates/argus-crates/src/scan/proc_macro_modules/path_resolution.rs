use super::*;

pub(in crate::scan) fn normalize_inline_module_directory(
    canonical_pkg_dir: &Path,
    base: &Path,
    explicit_path: &str,
) -> Result<PathBuf> {
    let explicit = Path::new(explicit_path);
    if explicit.as_os_str().is_empty() || explicit.is_absolute() {
        anyhow::bail!(
            "proc-macro inline #[path] must be a non-empty relative path: `{explicit_path}`"
        );
    }
    let mut resolved = base.to_path_buf();
    for component in explicit.components() {
        match component {
            Component::Normal(part) => resolved.push(part),
            Component::CurDir => {}
            Component::ParentDir => {
                inspect_proc_macro_traversal_component(canonical_pkg_dir, &resolved, true)?;
                if !resolved.pop() {
                    anyhow::bail!("proc-macro inline module path escapes crate root");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("proc-macro inline module path must be relative");
            }
        }
    }
    if resolved.as_os_str().is_empty() {
        anyhow::bail!("proc-macro inline module path is empty");
    }
    Ok(resolved)
}

pub(in crate::scan) fn resolve_conventional_module_path(
    canonical_pkg_dir: &Path,
    module_base: &Path,
    module_name: &str,
) -> Result<PathBuf> {
    let flat = module_base.join(format!("{module_name}.rs"));
    let nested = module_base.join(module_name).join("mod.rs");
    // Match rustc's two complete-path availability probes before applying the
    // scanner's stricter path policy. An incomplete alternative may traverse a
    // link, but the one selected complete candidate is always validated below.
    let flat_availability = classify_conventional_module_candidate(canonical_pkg_dir, &flat)?;
    let nested_availability = classify_conventional_module_candidate(canonical_pkg_dir, &nested)?;
    resolve_classified_conventional_module_path(
        canonical_pkg_dir,
        module_name,
        flat,
        flat_availability,
        nested,
        nested_availability,
    )
}

pub(in crate::scan) fn resolve_classified_conventional_module_path(
    canonical_pkg_dir: &Path,
    module_name: &str,
    flat: PathBuf,
    flat_availability: ConventionalCandidateAvailability,
    nested: PathBuf,
    nested_availability: ConventionalCandidateAvailability,
) -> Result<PathBuf> {
    match (flat_availability, nested_availability) {
        (
            ConventionalCandidateAvailability::Present,
            ConventionalCandidateAvailability::Present,
        ) => anyhow::bail!(
            "proc-macro module `{module_name}` is ambiguous: both {} and {} exist",
            flat.display(),
            nested.display()
        ),
        (
            ConventionalCandidateAvailability::Present,
            ConventionalCandidateAvailability::Unavailable(_),
        ) => validate_proc_macro_source_path(canonical_pkg_dir, &flat),
        (
            ConventionalCandidateAvailability::Unavailable(_),
            ConventionalCandidateAvailability::Present,
        ) => validate_proc_macro_source_path(canonical_pkg_dir, &nested),
        (
            ConventionalCandidateAvailability::Unavailable(flat_error),
            ConventionalCandidateAvailability::Unavailable(nested_error),
        ) => {
            if !conventional_candidate_unavailability_is_absence_like(&flat_error) {
                return Err(flat_error).with_context(|| {
                    format!(
                        "inspect conventional proc-macro source candidate {}",
                        canonical_pkg_dir.join(&flat).display()
                    )
                });
            }
            if !conventional_candidate_unavailability_is_absence_like(&nested_error) {
                return Err(nested_error).with_context(|| {
                    format!(
                        "inspect conventional proc-macro source candidate {}",
                        canonical_pkg_dir.join(&nested).display()
                    )
                });
            }
            anyhow::bail!(
                "proc-macro module `{module_name}` is missing: expected {} or {}",
                flat.display(),
                nested.display()
            )
        }
    }
}

pub(in crate::scan) fn resolve_explicit_module_path_from_base(
    canonical_pkg_dir: &Path,
    base_dir: &Path,
    explicit_path: &str,
    declaring_source: &str,
) -> Result<PathBuf> {
    let explicit = Path::new(explicit_path);
    if explicit.as_os_str().is_empty() || explicit.is_absolute() {
        anyhow::bail!("proc-macro #[path] must be a non-empty relative path: `{explicit_path}`");
    }
    let candidate_rel = resolve_proc_macro_module_traversal(canonical_pkg_dir, base_dir, explicit)
        .with_context(|| {
            format!("resolve proc-macro #[path] `{explicit_path}` from {declaring_source}")
        })?;
    validate_proc_macro_source_path(canonical_pkg_dir, &candidate_rel).with_context(|| {
        format!("resolve proc-macro #[path] `{explicit_path}` from {declaring_source}")
    })
}

pub(in crate::scan) fn resolve_proc_macro_module_traversal(
    canonical_pkg_dir: &Path,
    declaring_dir: &Path,
    explicit: &Path,
) -> Result<PathBuf> {
    let mut resolved_rel = PathBuf::new();
    for component in declaring_dir.components() {
        match component {
            Component::Normal(part) => {
                resolved_rel.push(part);
                inspect_proc_macro_traversal_component(canonical_pkg_dir, &resolved_rel, true)?;
            }
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("declaring proc-macro source directory must be normalized")
            }
        }
    }

    let components = explicit.components().collect::<Vec<_>>();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::Normal(part) => {
                resolved_rel.push(part);
                // Inspect before a later `..` can remove this component. Once
                // prior components are known to be real directories and not
                // links/reparse points, lexical pop matches filesystem traversal.
                inspect_proc_macro_traversal_component(
                    canonical_pkg_dir,
                    &resolved_rel,
                    index + 1 < components.len(),
                )?;
            }
            Component::CurDir => {}
            Component::ParentDir => {
                if !resolved_rel.pop() {
                    anyhow::bail!("proc-macro module path escapes crate root");
                }
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("proc-macro module path must be relative");
            }
        }
    }
    if resolved_rel.as_os_str().is_empty() {
        anyhow::bail!("proc-macro module path is empty");
    }
    Ok(resolved_rel)
}

pub(in crate::scan) fn inspect_proc_macro_traversal_component(
    canonical_pkg_dir: &Path,
    rel: &Path,
    must_be_directory: bool,
) -> Result<()> {
    let component_path = canonical_pkg_dir.join(rel);
    let metadata = std::fs::symlink_metadata(&component_path).with_context(|| {
        format!(
            "inspect proc-macro module path component {}",
            component_path.display()
        )
    })?;
    if metadata_is_symlink_or_reparse(&metadata) {
        anyhow::bail!(
            "proc-macro source path contains a symlink or reparse point: {}",
            component_path.display()
        );
    }
    if must_be_directory && !metadata.is_dir() {
        anyhow::bail!(
            "proc-macro module path component is not a directory: {}",
            component_path.display()
        );
    }
    Ok(())
}

#[derive(Debug)]
pub(in crate::scan) enum ConventionalCandidateAvailability {
    Present,
    Unavailable(std::io::Error),
}

pub(in crate::scan) fn classify_conventional_module_candidate(
    canonical_pkg_dir: &Path,
    rel: &Path,
) -> Result<ConventionalCandidateAvailability> {
    if rel
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!(
            "conventional proc-macro source path contains a non-normal component: {}",
            rel.display()
        );
    }
    let candidate = canonical_pkg_dir.join(rel);
    Ok(match std::fs::metadata(&candidate) {
        Ok(_) => ConventionalCandidateAvailability::Present,
        Err(error) => ConventionalCandidateAvailability::Unavailable(error),
    })
}

pub(in crate::scan) fn conventional_candidate_unavailability_is_absence_like(
    error: &std::io::Error,
) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) || io_error_is_filesystem_loop(error)
}

#[cfg(unix)]
pub(in crate::scan) fn io_error_is_filesystem_loop(error: &std::io::Error) -> bool {
    rustix::io::Errno::from_io_error(error) == Some(rustix::io::Errno::LOOP)
}

#[cfg(windows)]
pub(in crate::scan) fn io_error_is_filesystem_loop(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_ERROR_CANT_RESOLVE_FILENAME)
}

#[cfg(not(any(unix, windows)))]
pub(in crate::scan) fn io_error_is_filesystem_loop(_error: &std::io::Error) -> bool {
    false
}

pub(in crate::scan) fn validate_proc_macro_source_path(
    canonical_pkg_dir: &Path,
    rel: &Path,
) -> Result<PathBuf> {
    if rel
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        anyhow::bail!(
            "proc-macro source path contains a non-normal component: {}",
            rel.display()
        );
    }
    let candidate = canonical_pkg_dir.join(rel);
    let mut component_path = canonical_pkg_dir.to_path_buf();
    for component in rel.components() {
        let Component::Normal(part) = component else {
            unreachable!("proc-macro source components were validated above");
        };
        component_path.push(part);
        let metadata = std::fs::symlink_metadata(&component_path).with_context(|| {
            format!(
                "inspect proc-macro source path component {}",
                component_path.display()
            )
        })?;
        if metadata_is_symlink_or_reparse(&metadata) {
            anyhow::bail!(
                "proc-macro source path contains a symlink or reparse point: {}",
                component_path.display()
            );
        }
    }
    let resolved = std::fs::canonicalize(&candidate)
        .with_context(|| format!("resolve proc-macro source {}", candidate.display()))?;
    if !resolved.starts_with(canonical_pkg_dir) {
        anyhow::bail!(
            "proc-macro source escapes crate root: {} resolves to {}",
            candidate.display(),
            resolved.display()
        );
    }
    let metadata = std::fs::symlink_metadata(&candidate)
        .with_context(|| format!("inspect proc-macro source {}", candidate.display()))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!(
            "proc-macro source is not a regular file: {}",
            candidate.display()
        );
    }
    resolved
        .strip_prefix(canonical_pkg_dir)
        .map(Path::to_path_buf)
        .with_context(|| {
            format!(
                "derive on-disk proc-macro source identity for {}",
                resolved.display()
            )
        })
}

pub(in crate::scan) fn metadata_is_symlink_or_reparse(metadata: &std::fs::Metadata) -> bool {
    #[cfg(windows)]
    let windows_file_attributes = {
        use std::os::windows::fs::MetadataExt as _;
        metadata.file_attributes()
    };
    #[cfg(not(windows))]
    let windows_file_attributes = 0;

    link_metadata_indicates_symlink_or_reparse(
        metadata.file_type().is_symlink(),
        windows_file_attributes,
    )
}

pub(in crate::scan) fn link_metadata_indicates_symlink_or_reparse(
    is_symlink: bool,
    windows_file_attributes: u32,
) -> bool {
    is_symlink || windows_file_attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

pub(in crate::scan) fn path_to_manifest_rel(path: &Path) -> Result<String> {
    let raw = path.to_string_lossy().replace('\\', "/");
    normalize_manifest_relative_path(&raw, "resolved proc-macro module")
}
