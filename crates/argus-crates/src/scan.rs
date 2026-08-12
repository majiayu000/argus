//! Walk an extracted `.crate` tree and produce a `ScanReport`.
//!
//! What runs here:
//! - Ecosystem-agnostic content rules from `argus-rules` (credential-access,
//!   ai-context-poisoning, etc.) against every text file.
//! - Crates-specific rules from `crate::rules` against `build.rs` and
//!   proc-macro entry points.
//! - Cargo.toml manifest parsing for name, version, and proc-macro flag.

use crate::{finding, rules};
use anyhow::{Context, Result};
use argus_archive::extract_tarball;
use argus_core::{ArtifactKind, Finding, ScanReport, Severity};
use argus_rules::{looks_binary, scan_text_file, scan_text_files_with_context, RuleSession};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};

/// Crate paths whose contents the crates.io rules read.
fn is_crate_security_relevant(rel: &str) -> bool {
    rel.ends_with(".rs") || rel == "Cargo.toml" || rel.ends_with("/Cargo.toml")
}

const TEXT_MAX_BYTES: u64 = 1024 * 1024;
const MAX_PROC_MACRO_SOURCE_FILES: usize = 1024;
const MAX_PROC_MACRO_MODULE_DECLARATIONS: usize = 8192;
const MAX_PROC_MACRO_RESOLUTION_EDGES: usize = 4096;
const WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
#[cfg(windows)]
const WINDOWS_ERROR_CANT_RESOLVE_FILENAME: i32 = 1921;

/// Top-level: extract `.crate` + scan everything inside.
pub fn scan_crate_archive(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
) -> Result<ScanReport> {
    let rules = RuleSession::builtin()?;
    scan_crate_archive_with_rules(crate_bytes, dest_root, max_extracted_bytes, &rules)
}

pub fn scan_crate_archive_with_rules(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
) -> Result<ScanReport> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_crate_archive_with_rules_and_context(
        crate_bytes,
        dest_root,
        max_extracted_bytes,
        rules,
        &execution,
    )
}

pub fn scan_crate_archive_with_rules_and_context(
    crate_bytes: &[u8],
    dest_root: &Path,
    max_extracted_bytes: u64,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<ScanReport> {
    let pkg_dir = extract_tarball(crate_bytes, dest_root, max_extracted_bytes)
        .context("safe-extract .crate")?;
    let builtin = RuleSession::builtin()?;
    let mut scan = scan_extracted_crate_with_rules_and_context(&pkg_dir, &builtin, execution)?;
    rules
        .scan_directory_with_context(dest_root, &mut scan.findings, execution)
        .context("run configured rules on extracted .crate archive")?;
    rules.validate_external_limits(&scan.findings)?;
    rules.normalize_findings(&mut scan.findings);
    let decision = argus_rules::derive_decision_from_findings(&scan.findings);
    let mut report = ScanReport {
        artifact: ArtifactKind::PackageDir,
        path: pkg_dir,
        package_name: scan.name,
        package_version: scan.version,
        decision,
        findings: scan.findings,
        coordinate: None,
        intelligence: None,
        rules: None,
        vulnerability: None,
        risk: None,
    };
    rules.finalize_package(&mut report);
    Ok(report)
}

pub fn scan_extracted_crate(pkg_dir: &Path) -> Result<crate::ArtifactScan> {
    let rules = RuleSession::builtin()?;
    scan_extracted_crate_with_rules(pkg_dir, &rules)
}

pub fn scan_extracted_crate_with_rules(
    pkg_dir: &Path,
    rules: &RuleSession,
) -> Result<crate::ArtifactScan> {
    let execution = argus_core::ExecutionContext::serial()?;
    scan_extracted_crate_with_rules_and_context(pkg_dir, rules, &execution)
}

pub fn scan_extracted_crate_with_rules_and_context(
    pkg_dir: &Path,
    rules: &RuleSession,
    execution: &argus_core::ExecutionContext,
) -> Result<crate::ArtifactScan> {
    let mut findings: Vec<Finding> = Vec::new();
    let manifest = read_top_level_manifest(pkg_dir)?;
    let (name, version) = manifest
        .as_ref()
        .and_then(cargo_manifest_name_version)
        .unwrap_or((None, None));
    let is_proc_macro = manifest
        .as_ref()
        .map(cargo_manifest_is_proc_macro)
        .unwrap_or(false);
    let proc_macro_source_files = manifest
        .as_ref()
        .map(|manifest| collect_proc_macro_source_files(pkg_dir, manifest))
        .transpose()?
        .unwrap_or_default();
    let build_script_rel = manifest
        .as_ref()
        .map(cargo_manifest_build_script)
        .transpose()?
        .flatten();
    let mut build_script_seen: Option<String> = None;

    let (file_results, skipped) =
        scan_text_files_with_context(pkg_dir, TEXT_MAX_BYTES, execution, |file| {
            let mut per_file = Vec::new();
            scan_text_file(file, &mut per_file);
            let is_build_script = build_script_rel.as_deref() == Some(file.rel.as_str());
            if is_build_script {
                scan_build_rs(&file.content, &file.rel, &mut per_file);
                scan_rust_source(&file.content, &file.rel, &mut per_file);
            } else {
                if file.rel.ends_with(".rs") {
                    scan_rust_source(&file.content, &file.rel, &mut per_file);
                }
                if proc_macro_source_files.contains(&file.rel) {
                    scan_proc_macro_source(&file.content, &file.rel, &mut per_file);
                }
            }
            Ok::<_, anyhow::Error>((per_file, is_build_script.then(|| file.rel.clone())))
        })?;
    skipped.require_scanned("crate", is_crate_security_relevant)?;
    for (mut per_file, build_script) in file_results {
        build_script_seen = build_script_seen.take().or(build_script);
        findings.append(&mut per_file);
    }

    // Structural meta-findings.
    if let Some(rel) = build_script_seen {
        findings.push(finding(
            "build-rs-execution",
            Severity::Info,
            format!("crate declares build script `{rel}` — runs at consumer compile time"),
        ));
    }
    if is_proc_macro {
        findings.push(finding(
            "proc-macro-crate",
            Severity::Info,
            "crate declares `[lib] proc-macro = true` — code runs at consumer compile time",
        ));
    }

    rules
        .scan_directory_with_context(pkg_dir, &mut findings, execution)
        .context("run configured rules on extracted .crate")?;
    rules.validate_external_limits(&findings)?;
    rules.normalize_findings(&mut findings);

    Ok(crate::ArtifactScan {
        findings,
        name,
        version,
    })
}

#[derive(Debug, Deserialize)]
struct CargoManifest {
    package: Option<CargoPackage>,
    lib: Option<CargoLib>,
}

#[derive(Debug, Deserialize)]
struct CargoPackage {
    name: Option<String>,
    version: Option<String>,
    build: Option<CargoBuildField>,
}

#[derive(Debug, Deserialize)]
struct CargoLib {
    #[serde(rename = "proc-macro")]
    proc_macro: Option<bool>,
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum CargoBuildField {
    Bool(bool),
    Path(String),
}

fn read_top_level_manifest(pkg_dir: &Path) -> Result<Option<CargoManifest>> {
    let manifest_path = pkg_dir.join("Cargo.toml");
    // Read through one no-follow descriptor: a `Cargo.toml` symlinked out of
    // the extracted tree must not be followed, and the regular-file check
    // belongs on the descriptor that is actually read.
    let content = match argus_core::fs::read_bounded_utf8_regular_file(
        &manifest_path,
        TEXT_MAX_BYTES as usize,
    ) {
        Ok(content) => content,
        Err(_error) if !manifest_path.exists() => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("read {}", manifest_path.display()))
        }
    };
    toml::from_str(&content).with_context(|| format!("parse {}", manifest_path.display()))
}

fn cargo_manifest_name_version(
    manifest: &CargoManifest,
) -> Option<(Option<String>, Option<String>)> {
    let package = manifest.package.as_ref()?;
    Some((package.name.clone(), package.version.clone()))
}

fn cargo_manifest_is_proc_macro(manifest: &CargoManifest) -> bool {
    manifest
        .lib
        .as_ref()
        .and_then(|lib| lib.proc_macro)
        .unwrap_or(false)
}

fn cargo_manifest_proc_macro_lib_path(manifest: &CargoManifest) -> Result<Option<String>> {
    if !cargo_manifest_is_proc_macro(manifest) {
        return Ok(None);
    }
    let path = manifest
        .lib
        .as_ref()
        .and_then(|lib| lib.path.as_deref())
        .unwrap_or("src/lib.rs");
    normalize_manifest_relative_path(path, "Cargo.toml lib.path").map(Some)
}

fn cargo_manifest_build_script(manifest: &CargoManifest) -> Result<Option<String>> {
    let Some(package) = manifest.package.as_ref() else {
        return Ok(Some("build.rs".to_string()));
    };
    match package.build.as_ref() {
        Some(CargoBuildField::Bool(false)) => Ok(None),
        Some(CargoBuildField::Bool(true)) | None => Ok(Some("build.rs".to_string())),
        Some(CargoBuildField::Path(path)) => {
            normalize_manifest_relative_path(path, "Cargo.toml package.build").map(Some)
        }
    }
}

fn normalize_manifest_relative_path(raw: &str, field: &str) -> Result<String> {
    if raw.is_empty() {
        anyhow::bail!("{field} path is empty");
    }
    if raw.contains('\\') {
        anyhow::bail!("{field} path must use forward slashes");
    }
    let path = Path::new(raw);
    if path.is_absolute() {
        anyhow::bail!("{field} path must be relative");
    }

    let mut parts = Vec::new();
    for component in path.components() {
        match component {
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::CurDir => {}
            Component::ParentDir => {
                anyhow::bail!("{field} path must not contain `..`")
            }
            Component::RootDir | Component::Prefix(_) => {
                anyhow::bail!("{field} path must be relative")
            }
        }
    }
    if parts.is_empty() {
        anyhow::bail!("{field} path is empty");
    }
    Ok(parts.join("/"))
}

fn collect_proc_macro_source_files(
    pkg_dir: &Path,
    manifest: &CargoManifest,
) -> Result<BTreeSet<String>> {
    let Some(declared_root_rel) = cargo_manifest_proc_macro_lib_path(manifest)? else {
        return Ok(BTreeSet::new());
    };
    let canonical_pkg_dir = std::fs::canonicalize(pkg_dir)
        .with_context(|| format!("canonicalize crate root {}", pkg_dir.display()))?;
    let root_path =
        validate_proc_macro_source_path(&canonical_pkg_dir, Path::new(&declared_root_rel))?;
    let root_rel = path_to_manifest_rel(&root_path)?;
    let root_context = ProcMacroSourceContext::root(root_rel.clone());
    let mut source_files = BTreeSet::new();
    source_files.insert(root_rel.clone());
    let mut visited_contexts = BTreeSet::new();
    visited_contexts.insert(root_context.clone());
    let mut resolved_edges = BTreeSet::new();
    let mut pending = vec![root_context];
    let mut budgets = ProcMacroModuleBudgets::default();

    while let Some(context) = pending.pop() {
        let source_path =
            validate_proc_macro_source_path(&canonical_pkg_dir, Path::new(&context.source_rel))?;
        let abs = canonical_pkg_dir.join(&source_path);
        let content = argus_core::fs::read_bounded_utf8_regular_file(&abs, TEXT_MAX_BYTES as usize)
            .with_context(|| format!("read proc-macro source {}", abs.display()))?;
        if looks_binary(content.as_bytes()) {
            anyhow::bail!("proc-macro source appears binary: {}", abs.display());
        }
        let declarations = proc_macro_module_declarations(&content, &context, &mut budgets)
            .with_context(|| format!("parse proc-macro modules in {}", abs.display()))?;

        for declaration in declarations {
            if !resolved_edges.insert(declaration.lookup.clone()) {
                continue;
            }
            let module = declaration.resolve(&canonical_pkg_dir)?;
            let module_rel = path_to_manifest_rel(&module)?;
            if !source_files.contains(&module_rel) {
                if source_files.len() >= MAX_PROC_MACRO_SOURCE_FILES {
                    anyhow::bail!(
                        "proc-macro module graph exceeds {MAX_PROC_MACRO_SOURCE_FILES} source files"
                    );
                }
                source_files.insert(module_rel.clone());
            }
            let next_context = declaration.source_context(module_rel);
            if visited_contexts.insert(next_context.clone()) {
                pending.push(next_context);
            }
        }
    }

    Ok(source_files)
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ProcMacroSourceContext {
    source_rel: String,
    source_dir: PathBuf,
    module_dir: PathBuf,
}

impl ProcMacroSourceContext {
    fn root(source_rel: String) -> Self {
        let source_dir = Path::new(&source_rel)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        Self {
            source_rel,
            source_dir: source_dir.clone(),
            module_dir: source_dir,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ProcMacroModuleDeclaration {
    lookup: ProcMacroModuleLookup,
}

impl ProcMacroModuleDeclaration {
    fn resolve(&self, canonical_pkg_dir: &Path) -> Result<PathBuf> {
        match &self.lookup {
            ProcMacroModuleLookup::Conventional {
                module_base,
                module_name,
            } => resolve_conventional_module_path(canonical_pkg_dir, module_base, module_name),
            ProcMacroModuleLookup::Explicit {
                base_dir,
                explicit_path,
                declaring_source,
            } => resolve_explicit_module_path_from_base(
                canonical_pkg_dir,
                base_dir,
                explicit_path,
                declaring_source,
            ),
        }
    }

    fn source_context(&self, source_rel: String) -> ProcMacroSourceContext {
        let source_dir = Path::new(&source_rel)
            .parent()
            .unwrap_or_else(|| Path::new(""))
            .to_path_buf();
        let module_dir = match &self.lookup {
            ProcMacroModuleLookup::Conventional {
                module_base,
                module_name,
            } => module_base.join(module_name),
            ProcMacroModuleLookup::Explicit { .. } => source_dir.clone(),
        };
        ProcMacroSourceContext {
            source_rel,
            source_dir,
            module_dir,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum ProcMacroModuleLookup {
    Conventional {
        module_base: PathBuf,
        module_name: String,
    },
    Explicit {
        base_dir: PathBuf,
        explicit_path: String,
        declaring_source: String,
    },
}

#[derive(Default)]
struct ProcMacroModuleBudgets {
    declarations: usize,
    resolution_edges: usize,
}

impl ProcMacroModuleBudgets {
    fn note_declaration(&mut self) -> Result<()> {
        if self.declarations >= MAX_PROC_MACRO_MODULE_DECLARATIONS {
            anyhow::bail!(
                "proc-macro module declarations exceed {MAX_PROC_MACRO_MODULE_DECLARATIONS}"
            );
        }
        self.declarations += 1;
        Ok(())
    }

    fn note_resolution_edge(&mut self) -> Result<()> {
        if self.resolution_edges >= MAX_PROC_MACRO_RESOLUTION_EDGES {
            anyhow::bail!(
                "proc-macro module resolution edges exceed {MAX_PROC_MACRO_RESOLUTION_EDGES}"
            );
        }
        self.resolution_edges += 1;
        Ok(())
    }
}

#[derive(Clone)]
struct ProcMacroItemContext {
    conventional_base: PathBuf,
    explicit_base: PathBuf,
    source_rel: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum CfgEval {
    True,
    False,
    Unknown,
}

#[derive(Default)]
struct ModulePathPlan {
    unconditional_paths: Vec<String>,
    conditional_paths: Vec<(CfgEval, String)>,
}

fn proc_macro_module_declarations(
    source: &str,
    source_context: &ProcMacroSourceContext,
    budgets: &mut ProcMacroModuleBudgets,
) -> Result<Vec<ProcMacroModuleDeclaration>> {
    let syntax = syn::parse_file(source)?;
    let item_context = ProcMacroItemContext {
        conventional_base: source_context.module_dir.clone(),
        explicit_base: source_context.source_dir.clone(),
        source_rel: source_context.source_rel.clone(),
    };
    let mut declarations = Vec::new();
    collect_proc_macro_item_declarations(&syntax.items, &item_context, budgets, &mut declarations)?;
    Ok(declarations)
}

fn collect_proc_macro_item_declarations(
    items: &[syn::Item],
    context: &ProcMacroItemContext,
    budgets: &mut ProcMacroModuleBudgets,
    declarations: &mut Vec<ProcMacroModuleDeclaration>,
) -> Result<()> {
    for item in items {
        let syn::Item::Mod(module) = item else {
            continue;
        };
        if module_attrs_are_definitely_disabled(&module.attrs)? {
            continue;
        }

        budgets.note_declaration()?;
        let name = rust_module_ident_name(&module.ident);
        let path_plan = module_path_plan(&module.attrs)?;

        if let Some((_brace, inline_items)) = &module.content {
            for child_context in inline_module_contexts(context, &name, &path_plan)? {
                collect_proc_macro_item_declarations(
                    inline_items,
                    &child_context,
                    budgets,
                    declarations,
                )?;
            }
            continue;
        }

        for lookup in external_module_lookups(context, &name, &path_plan) {
            budgets.note_resolution_edge()?;
            declarations.push(ProcMacroModuleDeclaration { lookup });
        }
    }
    Ok(())
}

fn rust_module_ident_name(ident: &syn::Ident) -> String {
    let raw = ident.to_string();
    raw.strip_prefix("r#").unwrap_or(&raw).to_string()
}

fn external_module_lookups(
    context: &ProcMacroItemContext,
    name: &str,
    path_plan: &ModulePathPlan,
) -> Vec<ProcMacroModuleLookup> {
    let mut lookups = Vec::new();
    if conventional_lookup_is_potentially_active(path_plan) {
        lookups.push(ProcMacroModuleLookup::Conventional {
            module_base: context.conventional_base.clone(),
            module_name: name.to_string(),
        });
    }
    for path in potentially_active_explicit_paths(path_plan) {
        lookups.push(ProcMacroModuleLookup::Explicit {
            base_dir: context.explicit_base.clone(),
            explicit_path: path.clone(),
            declaring_source: context.source_rel.clone(),
        });
    }
    lookups
}

fn inline_module_contexts(
    context: &ProcMacroItemContext,
    name: &str,
    path_plan: &ModulePathPlan,
) -> Result<Vec<ProcMacroItemContext>> {
    let mut contexts = Vec::new();
    if conventional_lookup_is_potentially_active(path_plan) {
        let base = context.conventional_base.join(name);
        contexts.push(ProcMacroItemContext {
            conventional_base: base.clone(),
            explicit_base: base,
            source_rel: context.source_rel.clone(),
        });
    }
    for path in potentially_active_explicit_paths(path_plan) {
        let base = normalize_inline_module_directory(&context.explicit_base, path)?;
        contexts.push(ProcMacroItemContext {
            conventional_base: base.clone(),
            explicit_base: base,
            source_rel: context.source_rel.clone(),
        });
    }
    Ok(contexts)
}

fn conventional_lookup_is_potentially_active(path_plan: &ModulePathPlan) -> bool {
    path_plan.unconditional_paths.is_empty()
        && !path_plan
            .conditional_paths
            .iter()
            .any(|(condition, _path)| *condition == CfgEval::True)
}

fn potentially_active_explicit_paths(path_plan: &ModulePathPlan) -> impl Iterator<Item = &String> {
    path_plan.unconditional_paths.iter().chain(
        path_plan
            .conditional_paths
            .iter()
            .filter(|(condition, _path)| *condition != CfgEval::False)
            .map(|(_condition, path)| path),
    )
}

fn module_attrs_are_definitely_disabled(attrs: &[syn::Attribute]) -> Result<bool> {
    for attr in attrs {
        if !attr.path().is_ident("cfg") {
            continue;
        }
        let meta = attr.parse_args::<syn::Meta>()?;
        if eval_cfg_meta(&meta)? == CfgEval::False {
            return Ok(true);
        }
    }
    Ok(false)
}

fn module_path_plan(attrs: &[syn::Attribute]) -> Result<ModulePathPlan> {
    let mut plan = ModulePathPlan::default();
    for attr in attrs {
        if attr.path().is_ident("path") {
            plan.unconditional_paths.push(path_attr_value(attr)?);
        } else if attr.path().is_ident("cfg_attr") {
            collect_cfg_attr_path_values(attr, &mut plan)?;
        }
    }
    Ok(plan)
}

fn collect_cfg_attr_path_values(attr: &syn::Attribute, plan: &mut ModulePathPlan) -> Result<()> {
    let metas = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    )?;
    let mut metas = metas.iter();
    let condition = metas
        .next()
        .context("cfg_attr on proc-macro module has no condition")?;
    let condition = eval_cfg_meta(condition)?;
    if condition == CfgEval::False {
        return Ok(());
    }
    for meta in metas {
        if meta.path().is_ident("path") {
            plan.conditional_paths
                .push((condition, path_meta_value(meta)?));
        }
    }
    Ok(())
}

fn path_attr_value(attr: &syn::Attribute) -> Result<String> {
    path_meta_value(&attr.meta)
}

fn path_meta_value(meta: &syn::Meta) -> Result<String> {
    let syn::Meta::NameValue(name_value) = meta else {
        anyhow::bail!("Rust path attribute must contain a string literal");
    };
    let syn::Expr::Lit(expr_lit) = &name_value.value else {
        anyhow::bail!("Rust path attribute must contain a string literal");
    };
    let syn::Lit::Str(value) = &expr_lit.lit else {
        anyhow::bail!("Rust path attribute must contain a string literal");
    };
    Ok(value.value())
}

fn eval_cfg_meta(meta: &syn::Meta) -> Result<CfgEval> {
    let syn::Meta::List(list) = meta else {
        return Ok(CfgEval::Unknown);
    };
    if list.path.is_ident("any") {
        return eval_cfg_any(list);
    }
    if list.path.is_ident("all") {
        return eval_cfg_all(list);
    }
    if list.path.is_ident("not") {
        return eval_cfg_not(list);
    }
    Ok(CfgEval::Unknown)
}

fn eval_cfg_any(list: &syn::MetaList) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    if nested.is_empty() {
        return Ok(CfgEval::False);
    }
    let mut saw_unknown = false;
    for meta in nested {
        match eval_cfg_meta(&meta)? {
            CfgEval::True => return Ok(CfgEval::True),
            CfgEval::False => {}
            CfgEval::Unknown => saw_unknown = true,
        }
    }
    Ok(if saw_unknown {
        CfgEval::Unknown
    } else {
        CfgEval::False
    })
}

fn eval_cfg_all(list: &syn::MetaList) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    let mut saw_unknown = false;
    for meta in nested {
        match eval_cfg_meta(&meta)? {
            CfgEval::True => {}
            CfgEval::False => return Ok(CfgEval::False),
            CfgEval::Unknown => saw_unknown = true,
        }
    }
    Ok(if saw_unknown {
        CfgEval::Unknown
    } else {
        CfgEval::True
    })
}

fn eval_cfg_not(list: &syn::MetaList) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    if nested.len() != 1 {
        return Ok(CfgEval::Unknown);
    }
    Ok(match eval_cfg_meta(&nested[0])? {
        CfgEval::True => CfgEval::False,
        CfgEval::False => CfgEval::True,
        CfgEval::Unknown => CfgEval::Unknown,
    })
}

fn parse_cfg_list(
    list: &syn::MetaList,
) -> Result<syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>> {
    list.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .map_err(anyhow::Error::from)
}

fn normalize_inline_module_directory(base: &Path, explicit_path: &str) -> Result<PathBuf> {
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

fn resolve_conventional_module_path(
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

fn resolve_classified_conventional_module_path(
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

fn resolve_explicit_module_path_from_base(
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

fn resolve_proc_macro_module_traversal(
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

fn inspect_proc_macro_traversal_component(
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
enum ConventionalCandidateAvailability {
    Present,
    Unavailable(std::io::Error),
}

fn classify_conventional_module_candidate(
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

fn conventional_candidate_unavailability_is_absence_like(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
    ) || io_error_is_filesystem_loop(error)
}

#[cfg(unix)]
fn io_error_is_filesystem_loop(error: &std::io::Error) -> bool {
    rustix::io::Errno::from_io_error(error) == Some(rustix::io::Errno::LOOP)
}

#[cfg(windows)]
fn io_error_is_filesystem_loop(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(WINDOWS_ERROR_CANT_RESOLVE_FILENAME)
}

#[cfg(not(any(unix, windows)))]
fn io_error_is_filesystem_loop(_error: &std::io::Error) -> bool {
    false
}

fn validate_proc_macro_source_path(canonical_pkg_dir: &Path, rel: &Path) -> Result<PathBuf> {
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

fn metadata_is_symlink_or_reparse(metadata: &std::fs::Metadata) -> bool {
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

fn link_metadata_indicates_symlink_or_reparse(
    is_symlink: bool,
    windows_file_attributes: u32,
) -> bool {
    is_symlink || windows_file_attributes & WINDOWS_FILE_ATTRIBUTE_REPARSE_POINT != 0
}

fn path_to_manifest_rel(path: &Path) -> Result<String> {
    let raw = path.to_string_lossy().replace('\\', "/");
    normalize_manifest_relative_path(&raw, "resolved proc-macro module")
}

fn scan_build_rs(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    if rules::build_rs_subprocess_regex().is_match(content) {
        findings.push(finding(
            "build-rs-subprocess",
            Severity::Critical,
            format!("`{rel}` invokes std::process::Command at compile time"),
        ));
    }
    let executable_code = rules::mask_rust_comments_and_literals(content);
    if rules::build_rs_network_regex().is_match(&executable_code) {
        findings.push(finding(
            "build-rs-network",
            Severity::Critical,
            format!("`{rel}` reaches the network at compile time (reqwest/ureq/hyper/TcpStream)"),
        ));
    }
}

fn scan_proc_macro_source(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    let executable_code = rules::mask_rust_comments_and_literals(content);
    if rules::build_rs_network_regex().is_match(&executable_code) {
        findings.push(finding(
            "proc-macro-network",
            Severity::Critical,
            format!(
                "`{rel}` reaches the network from proc-macro source that runs at consumer compile time"
            ),
        ));
    }
}

fn scan_rust_source(content: &str, rel: &str, findings: &mut Vec<Finding>) {
    let has_include_bytes = rules::include_bytes_regex().is_match(content);
    let has_xor_loop = rules::xor_loop_regex().is_match(content);
    if has_include_bytes && has_xor_loop {
        findings.push(finding(
            "build-rs-include-bytes",
            Severity::Critical,
            format!("`{rel}` embeds a binary blob via `include_bytes!` and contains an XOR decrypt loop — classic payload-decryption shape"),
        ));
    } else if has_xor_loop {
        findings.push(finding(
            "xor-decryption-loop",
            Severity::High,
            format!("`{rel}` contains a byte-by-byte XOR decrypt loop"),
        ));
    } else if has_include_bytes {
        findings.push(finding(
            "embedded-binary-blob",
            Severity::Info,
            format!("`{rel}` embeds binary bytes via `include_bytes!` — legitimate for fonts/configs but worth a glance"),
        ));
    }
}

#[cfg(test)]
mod tests;
