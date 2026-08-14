use super::*;

mod attributes;
mod collector;
mod path_resolution;
use collector::*;
pub(super) use path_resolution::*;

pub(super) fn collect_proc_macro_source_files(
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
    let edition = cargo_manifest_macro_rules_edition(manifest)?;

    while let Some(context) = pending.pop() {
        let source_path =
            validate_proc_macro_source_path(&canonical_pkg_dir, Path::new(&context.source_rel))?;
        let abs = canonical_pkg_dir.join(&source_path);
        let content = argus_core::fs::read_bounded_utf8_regular_file(&abs, TEXT_MAX_BYTES as usize)
            .with_context(|| format!("read proc-macro source {}", abs.display()))?;
        if looks_binary(content.as_bytes()) {
            anyhow::bail!("proc-macro source appears binary: {}", abs.display());
        }
        let declarations = proc_macro_module_declarations(
            &content,
            &context,
            &canonical_pkg_dir,
            &mut budgets,
            edition,
        )
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

fn cargo_manifest_macro_rules_edition(
    manifest: &CargoManifest,
) -> Result<super::macro_expansion::MacroRulesEdition> {
    use super::macro_expansion::MacroRulesEdition;

    let edition = manifest
        .package
        .as_ref()
        .and_then(|package| package.edition.as_ref());
    let Some(edition) = edition else {
        return Ok(MacroRulesEdition::Edition2015);
    };
    let Some(edition) = edition.as_str() else {
        anyhow::bail!("proc-macro package edition is inherited or is not a string");
    };
    match edition {
        "2015" => Ok(MacroRulesEdition::Edition2015),
        "2018" => Ok(MacroRulesEdition::Edition2018),
        "2021" => Ok(MacroRulesEdition::Edition2021),
        "2024" => Ok(MacroRulesEdition::Edition2024),
        other => anyhow::bail!("unsupported proc-macro package edition `{other}`"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(super) struct ProcMacroSourceContext {
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
pub(super) struct ProcMacroModuleDeclaration {
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
pub(super) enum ProcMacroModuleLookup {
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
pub(super) struct ProcMacroModuleBudgets {
    declarations: usize,
    resolution_edges: usize,
    expansions: usize,
    expanded_tokens: usize,
    expansion_depth: usize,
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
pub(super) struct ProcMacroItemContext {
    conventional_base: PathBuf,
    explicit_base: PathBuf,
    source_rel: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub(super) enum CfgEval {
    True,
    False,
    Unknown,
}

#[derive(Default)]
pub(super) struct ModulePathPlan {
    unconditional_paths: Vec<String>,
    conditional_paths: Vec<(CfgEval, String)>,
}

pub(super) fn proc_macro_module_declarations(
    source: &str,
    source_context: &ProcMacroSourceContext,
    canonical_pkg_dir: &Path,
    budgets: &mut ProcMacroModuleBudgets,
    edition: super::macro_expansion::MacroRulesEdition,
) -> Result<Vec<ProcMacroModuleDeclaration>> {
    let syntax = syn::parse_file(source)?;
    attributes::validate_proc_macro_attributes(&syntax.attrs, |_| false)?;
    let item_context = ProcMacroItemContext {
        conventional_base: source_context.module_dir.clone(),
        explicit_base: source_context.source_dir.clone(),
        source_rel: source_context.source_rel.clone(),
    };
    let mut declarations = Vec::new();
    collect_proc_macro_item_declarations(
        &syntax.items,
        &item_context,
        canonical_pkg_dir,
        budgets,
        &mut declarations,
        edition,
    )?;
    Ok(declarations)
}

pub(super) fn item_attributes(item: &syn::Item) -> Option<&[syn::Attribute]> {
    match item {
        syn::Item::Const(item) => Some(&item.attrs),
        syn::Item::Enum(item) => Some(&item.attrs),
        syn::Item::ExternCrate(item) => Some(&item.attrs),
        syn::Item::Fn(item) => Some(&item.attrs),
        syn::Item::ForeignMod(item) => Some(&item.attrs),
        syn::Item::Impl(item) => Some(&item.attrs),
        syn::Item::Macro(item) => Some(&item.attrs),
        syn::Item::Mod(item) => Some(&item.attrs),
        syn::Item::Static(item) => Some(&item.attrs),
        syn::Item::Struct(item) => Some(&item.attrs),
        syn::Item::Trait(item) => Some(&item.attrs),
        syn::Item::TraitAlias(item) => Some(&item.attrs),
        syn::Item::Type(item) => Some(&item.attrs),
        syn::Item::Union(item) => Some(&item.attrs),
        syn::Item::Use(item) => Some(&item.attrs),
        syn::Item::Verbatim(_) => None,
        _ => None,
    }
}

pub(super) fn impl_item_attributes(item: &syn::ImplItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::ImplItem::Const(item) => Some(&item.attrs),
        syn::ImplItem::Fn(item) => Some(&item.attrs),
        syn::ImplItem::Type(item) => Some(&item.attrs),
        syn::ImplItem::Macro(item) => Some(&item.attrs),
        syn::ImplItem::Verbatim(_) => None,
        _ => None,
    }
}

pub(super) fn trait_item_attributes(item: &syn::TraitItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::TraitItem::Const(item) => Some(&item.attrs),
        syn::TraitItem::Fn(item) => Some(&item.attrs),
        syn::TraitItem::Type(item) => Some(&item.attrs),
        syn::TraitItem::Macro(item) => Some(&item.attrs),
        syn::TraitItem::Verbatim(_) => None,
        _ => None,
    }
}

pub(super) fn foreign_item_attributes(item: &syn::ForeignItem) -> Option<&[syn::Attribute]> {
    match item {
        syn::ForeignItem::Fn(item) => Some(&item.attrs),
        syn::ForeignItem::Static(item) => Some(&item.attrs),
        syn::ForeignItem::Type(item) => Some(&item.attrs),
        syn::ForeignItem::Macro(item) => Some(&item.attrs),
        syn::ForeignItem::Verbatim(_) => None,
        _ => None,
    }
}

pub(super) fn rust_module_ident_name(ident: &syn::Ident) -> String {
    let raw = ident.to_string();
    raw.strip_prefix("r#").unwrap_or(&raw).to_string()
}

fn rust_path_display(path: &syn::Path) -> String {
    path.segments
        .iter()
        .map(|segment| segment.ident.to_string())
        .collect::<Vec<_>>()
        .join("::")
}

pub(super) fn external_module_lookups(
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

pub(super) fn inline_module_contexts(
    context: &ProcMacroItemContext,
    name: &str,
    path_plan: &ModulePathPlan,
    canonical_pkg_dir: &Path,
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
        let base =
            normalize_inline_module_directory(canonical_pkg_dir, &context.explicit_base, path)?;
        contexts.push(ProcMacroItemContext {
            conventional_base: base.clone(),
            explicit_base: base,
            source_rel: context.source_rel.clone(),
        });
    }
    Ok(contexts)
}

pub(super) fn conventional_lookup_is_potentially_active(path_plan: &ModulePathPlan) -> bool {
    path_plan.unconditional_paths.is_empty()
        && !path_plan
            .conditional_paths
            .iter()
            .any(|(condition, _path)| *condition == CfgEval::True)
}

pub(super) fn potentially_active_explicit_paths(
    path_plan: &ModulePathPlan,
) -> impl Iterator<Item = &String> {
    path_plan.unconditional_paths.iter().chain(
        path_plan
            .conditional_paths
            .iter()
            .filter(|(condition, _path)| *condition != CfgEval::False)
            .map(|(_condition, path)| path),
    )
}

pub(super) fn module_attrs_are_definitely_disabled(attrs: &[syn::Attribute]) -> Result<bool> {
    Ok(item_cfg_activation(attrs)? == CfgEval::False)
}

pub(super) fn item_cfg_activation(attrs: &[syn::Attribute]) -> Result<CfgEval> {
    let mut activation = CfgEval::True;
    for attribute in attrs {
        activation = cfg_eval_and(activation, cfg_gate_activation(&attribute.meta, 0)?);
        if activation == CfgEval::False {
            break;
        }
    }
    Ok(activation)
}

fn cfg_gate_activation(meta: &syn::Meta, depth: usize) -> Result<CfgEval> {
    if depth > MAX_PROC_MACRO_META_DEPTH {
        anyhow::bail!("proc-macro cfg_attr nesting exceeds {MAX_PROC_MACRO_META_DEPTH} levels");
    }
    if meta.path().is_ident("cfg") {
        let syn::Meta::List(list) = meta else {
            anyhow::bail!("cfg must contain a predicate");
        };
        return eval_cfg_meta(&syn::parse2(list.tokens.clone())?);
    }
    if meta.path().is_ident("cfg_attr") {
        let syn::Meta::List(list) = meta else {
            anyhow::bail!("nested cfg_attr must contain arguments");
        };
        let metas = parse_cfg_list(list)?;
        let mut metas = metas.iter();
        let condition = metas.next().context("nested cfg_attr has no condition")?;
        let condition = eval_cfg_meta(condition)?;
        if condition == CfgEval::False {
            return Ok(CfgEval::True);
        }
        let mut applied_activation = CfgEval::True;
        for nested in metas {
            applied_activation =
                cfg_eval_and(applied_activation, cfg_gate_activation(nested, depth + 1)?);
            if applied_activation == CfgEval::False {
                break;
            }
        }
        return Ok(match condition {
            CfgEval::True => applied_activation,
            CfgEval::Unknown if applied_activation == CfgEval::True => CfgEval::True,
            CfgEval::Unknown => CfgEval::Unknown,
            CfgEval::False => CfgEval::True,
        });
    }
    Ok(CfgEval::True)
}

pub(super) fn module_path_plan(attrs: &[syn::Attribute]) -> Result<ModulePathPlan> {
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

pub(super) fn collect_cfg_attr_path_values(
    attr: &syn::Attribute,
    plan: &mut ModulePathPlan,
) -> Result<()> {
    let metas = attr.parse_args_with(
        syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated,
    )?;
    let mut metas = metas.iter();
    let condition = metas
        .next()
        .context("cfg_attr on proc-macro module has no condition")?;
    let condition = eval_cfg_meta(condition)?;
    for meta in metas {
        collect_conditional_path_meta(meta, condition, plan, 0)?;
    }
    Ok(())
}

pub(super) fn collect_conditional_path_meta(
    meta: &syn::Meta,
    inherited_condition: CfgEval,
    plan: &mut ModulePathPlan,
    depth: usize,
) -> Result<()> {
    if depth > MAX_PROC_MACRO_META_DEPTH {
        anyhow::bail!("proc-macro cfg_attr nesting exceeds {MAX_PROC_MACRO_META_DEPTH} levels");
    }
    if inherited_condition == CfgEval::False {
        return Ok(());
    }
    if meta.path().is_ident("path") {
        plan.conditional_paths
            .push((inherited_condition, path_meta_value(meta)?));
        return Ok(());
    }
    if !meta.path().is_ident("cfg_attr") {
        return Ok(());
    }

    let syn::Meta::List(list) = meta else {
        anyhow::bail!("nested cfg_attr on proc-macro module must contain arguments");
    };
    let metas = parse_cfg_list(list)?;
    let mut metas = metas.iter();
    let condition = metas
        .next()
        .context("nested cfg_attr on proc-macro module has no condition")?;
    let condition = cfg_eval_and(inherited_condition, eval_cfg_meta(condition)?);
    for meta in metas {
        collect_conditional_path_meta(meta, condition, plan, depth + 1)?;
    }
    Ok(())
}

pub(super) fn cfg_eval_and(left: CfgEval, right: CfgEval) -> CfgEval {
    match (left, right) {
        (CfgEval::False, _) | (_, CfgEval::False) => CfgEval::False,
        (CfgEval::True, CfgEval::True) => CfgEval::True,
        _ => CfgEval::Unknown,
    }
}

pub(super) fn path_attr_value(attr: &syn::Attribute) -> Result<String> {
    path_meta_value(&attr.meta)
}

pub(super) fn path_meta_value(meta: &syn::Meta) -> Result<String> {
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

pub(super) fn eval_cfg_meta(meta: &syn::Meta) -> Result<CfgEval> {
    eval_cfg_meta_at_depth(meta, 0)
}

pub(super) fn eval_cfg_meta_at_depth(meta: &syn::Meta, depth: usize) -> Result<CfgEval> {
    if depth > MAX_PROC_MACRO_META_DEPTH {
        anyhow::bail!("proc-macro cfg expression exceeds {MAX_PROC_MACRO_META_DEPTH} levels");
    }
    let syn::Meta::List(list) = meta else {
        return Ok(CfgEval::Unknown);
    };
    if list.path.is_ident("any") {
        return eval_cfg_any(list, depth + 1);
    }
    if list.path.is_ident("all") {
        return eval_cfg_all(list, depth + 1);
    }
    if list.path.is_ident("not") {
        return eval_cfg_not(list, depth + 1);
    }
    Ok(CfgEval::Unknown)
}

pub(super) fn eval_cfg_any(list: &syn::MetaList, depth: usize) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    if nested.is_empty() {
        return Ok(CfgEval::False);
    }
    let mut saw_unknown = false;
    for meta in nested {
        match eval_cfg_meta_at_depth(&meta, depth)? {
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

pub(super) fn eval_cfg_all(list: &syn::MetaList, depth: usize) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    let mut saw_unknown = false;
    for meta in nested {
        match eval_cfg_meta_at_depth(&meta, depth)? {
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

pub(super) fn eval_cfg_not(list: &syn::MetaList, depth: usize) -> Result<CfgEval> {
    let nested = parse_cfg_list(list)?;
    if nested.len() != 1 {
        return Ok(CfgEval::Unknown);
    }
    Ok(match eval_cfg_meta_at_depth(&nested[0], depth)? {
        CfgEval::True => CfgEval::False,
        CfgEval::False => CfgEval::True,
        CfgEval::Unknown => CfgEval::Unknown,
    })
}

pub(super) fn parse_cfg_list(
    list: &syn::MetaList,
) -> Result<syn::punctuated::Punctuated<syn::Meta, syn::Token![,]>> {
    list.parse_args_with(syn::punctuated::Punctuated::<syn::Meta, syn::Token![,]>::parse_terminated)
        .map_err(anyhow::Error::from)
}
