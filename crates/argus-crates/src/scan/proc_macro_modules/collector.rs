use super::super::macro_expansion::{MacroRulesDefinition, MacroRulesEdition, OpaqueExpansion};
use super::attributes::{expression_attributes, validate_proc_macro_attributes};
use super::*;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

const MAX_EXPANSIONS: usize = 4096;
const MAX_EXPANDED_TOKENS: usize = 65_536;
const MAX_EXPANSION_DEPTH: usize = 32;

impl ProcMacroModuleBudgets {
    fn enter(&mut self) -> Result<usize> {
        if self.expansions >= MAX_EXPANSIONS {
            anyhow::bail!("local proc-macro expansion count exceeds {MAX_EXPANSIONS}");
        }
        if self.expansion_depth >= MAX_EXPANSION_DEPTH {
            anyhow::bail!("local proc-macro expansion nesting exceeds {MAX_EXPANSION_DEPTH}");
        }
        self.expansions += 1;
        self.expansion_depth += 1;
        Ok(MAX_EXPANDED_TOKENS - self.expanded_tokens)
    }

    fn note_expanded_tokens(&mut self, token_count: usize) -> Result<()> {
        if self.expanded_tokens.saturating_add(token_count) > MAX_EXPANDED_TOKENS {
            anyhow::bail!("local proc-macro expansion output exceeds {MAX_EXPANDED_TOKENS} tokens");
        }
        self.expanded_tokens += token_count;
        Ok(())
    }

    fn leave(&mut self) {
        self.expansion_depth = self.expansion_depth.saturating_sub(1);
    }
}

pub(super) fn collect_proc_macro_item_declarations(
    items: &[syn::Item],
    context: &ProcMacroItemContext,
    canonical_pkg_dir: &Path,
    budgets: &mut ProcMacroModuleBudgets,
    declarations: &mut Vec<ProcMacroModuleDeclaration>,
    inherited_macro_scopes: &[Rc<MacroScope>],
    edition: MacroRulesEdition,
) -> Result<()> {
    let mut exported_macros = BTreeMap::new();
    collect_exported_macros(items, &mut exported_macros, edition)?;
    let root_revision = budgets.next_scope_revision()?;
    let mut root_scope = MacroScope::for_items(items, root_revision)?;
    root_scope.exported_definitions = Rc::new(exported_macros);
    let mut macro_scopes = inherited_macro_scopes.to_vec();
    macro_scopes.push(Rc::new(root_scope));
    collect_items_with_state(
        items,
        context,
        canonical_pkg_dir,
        budgets,
        declarations,
        &macro_scopes,
        edition,
    )
}

fn collect_exported_macros(
    items: &[syn::Item],
    exported: &mut BTreeMap<String, DeferredMacroRulesDefinition>,
    edition: MacroRulesEdition,
) -> Result<()> {
    for item in items {
        if item_attributes(item)
            .map(module_attrs_are_definitely_disabled)
            .transpose()?
            .unwrap_or(false)
        {
            continue;
        }
        match item {
            syn::Item::Macro(item)
                if item.mac.path.is_ident("macro_rules")
                    && item.ident.is_some()
                    && item
                        .attrs
                        .iter()
                        .any(|attribute| attribute.path().is_ident("macro_export")) =>
            {
                reject_local_inner_macros(&item.attrs)?;
                let name = item
                    .ident
                    .as_ref()
                    .ok_or_else(|| OpaqueExpansion::new("macro_rules export has no name"))?
                    .to_string();
                let definition = DeferredMacroRulesDefinition {
                    tokens: item.mac.tokens.clone(),
                    edition,
                };
                if exported.insert(name.clone(), definition).is_some() {
                    return Err(OpaqueExpansion::new(format!(
                        "multiple potentially active #[macro_export] definitions are named `{name}`"
                    ))
                    .into());
                }
            }
            syn::Item::Mod(module) => {
                if let Some((_brace, children)) = &module.content {
                    collect_exported_macros(children, exported, edition)?;
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn collect_items_with_state(
    items: &[syn::Item],
    context: &ProcMacroItemContext,
    canonical_pkg_dir: &Path,
    budgets: &mut ProcMacroModuleBudgets,
    declarations: &mut Vec<ProcMacroModuleDeclaration>,
    inherited_macro_scopes: &[Rc<MacroScope>],
    edition: MacroRulesEdition,
) -> Result<()> {
    let mut collector = ProcMacroModuleCollector {
        context,
        canonical_pkg_dir,
        budgets,
        declarations,
        macro_scopes: inherited_macro_scopes.to_vec(),
        edition,
        error: None,
    };
    for item in items {
        collector.visit_item(item);
        if collector.error.is_some() {
            break;
        }
    }
    collector.error.map_or(Ok(()), Err)
}

struct ProcMacroModuleCollector<'a> {
    context: &'a ProcMacroItemContext,
    canonical_pkg_dir: &'a Path,
    budgets: &'a mut ProcMacroModuleBudgets,
    declarations: &'a mut Vec<ProcMacroModuleDeclaration>,
    macro_scopes: Vec<Rc<MacroScope>>,
    edition: MacroRulesEdition,
    error: Option<anyhow::Error>,
}

impl ProcMacroModuleCollector<'_> {
    fn validate_associated_item_attributes(
        &mut self,
        attributes: Option<&[syn::Attribute]>,
        unsupported_syntax: bool,
    ) -> bool {
        if self.error.is_some() {
            return false;
        }
        if unsupported_syntax {
            self.error = Some(
                OpaqueExpansion::new(
                    "unsupported Rust associated item syntax may emit modules and cannot be traversed statically",
                )
                .into(),
            );
            return false;
        }
        let Some(attributes) = attributes else {
            return true;
        };
        match module_attrs_are_definitely_disabled(attributes) {
            Ok(true) => return false,
            Ok(false) => {}
            Err(error) => {
                self.error = Some(error);
                return false;
            }
        }
        if let Err(error) =
            validate_proc_macro_attributes(attributes, |name| self.macro_name_may_be_imported(name))
        {
            self.error = Some(error);
            return false;
        }
        true
    }

    fn collect_module(&mut self, module: &syn::ItemMod) -> Result<()> {
        if module_attrs_are_definitely_disabled(&module.attrs)? {
            return Ok(());
        }
        self.budgets.note_declaration()?;
        let name = rust_module_ident_name(&module.ident);
        let path_plan = module_path_plan(&module.attrs)?;
        if let Some((_brace, inline_items)) = &module.content {
            for child_context in
                inline_module_contexts(self.context, &name, &path_plan, self.canonical_pkg_dir)?
            {
                let mut child_scopes = self.macro_scopes.clone();
                let child_revision = self.budgets.next_scope_revision()?;
                child_scopes.push(Rc::new(MacroScope::for_items(
                    inline_items,
                    child_revision,
                )?));
                collect_items_with_state(
                    inline_items,
                    &child_context,
                    self.canonical_pkg_dir,
                    self.budgets,
                    self.declarations,
                    &child_scopes,
                    self.edition,
                )?;
            }
            return Ok(());
        }
        let inherited_macro_scopes: Vec<_> = self
            .macro_scopes
            .iter()
            .map(|scope| scope.for_child_module())
            .collect();
        let inherited_scope_revisions: Vec<_> = inherited_macro_scopes
            .iter()
            .filter(|scope| scope.affects_child_macro_resolution())
            .map(|scope| scope.revision)
            .collect();
        for lookup in external_module_lookups(self.context, &name, &path_plan) {
            self.budgets.note_resolution_edge()?;
            self.budgets
                .note_retained_scope_entries(inherited_macro_scopes.len())?;
            self.declarations.push(ProcMacroModuleDeclaration {
                lookup,
                inherited_macro_scopes: inherited_macro_scopes.clone(),
                inherited_scope_revisions: inherited_scope_revisions.clone(),
            });
        }
        Ok(())
    }

    fn define_macro(&mut self, item: &syn::ItemMacro) -> Result<()> {
        reject_local_inner_macros(&item.attrs)?;
        let name = item
            .ident
            .as_ref()
            .context("macro_rules definition has no name")?
            .to_string();
        let is_exported = has_attribute(&item.attrs, "macro_export");
        let activation = item_cfg_activation(&item.attrs)?;
        let conflicts_with_visible_candidate = self.macro_scopes.iter().rev().any(|scope| {
            scope.definitions.contains_key(&name)
                || (!is_exported && scope.exported_definitions.contains_key(&name))
                || scope.macro_use_revision.is_some()
                || scope.macro_use_prelude_candidate
        });
        let definition = DeferredMacroRulesDefinition {
            tokens: item.mac.tokens.clone(),
            edition: self.edition,
        };
        let revision = self.budgets.next_scope_revision()?;
        let binding = if activation == CfgEval::Unknown && conflicts_with_visible_candidate {
            MacroBinding::Ambiguous
        } else {
            MacroBinding::Known {
                definition,
                revision,
            }
        };
        let snapshot_entries = self
            .macro_scopes
            .last()
            .filter(|scope| Rc::strong_count(&scope.definitions) > 1)
            .map_or(0, |scope| scope.definitions.len());
        self.budgets.note_scope_snapshot_entries(snapshot_entries)?;
        let scope = self
            .macro_scopes
            .last_mut()
            .context("local macro scope stack is empty")?;
        let scope = Rc::make_mut(scope);
        Rc::make_mut(&mut scope.definitions).insert(name, binding);
        scope.revision = revision;
        Ok(())
    }

    fn note_macro_use_module(&mut self) -> Result<()> {
        let revision = self.budgets.next_scope_revision()?;
        let scope = self
            .macro_scopes
            .last_mut()
            .context("local macro scope stack is empty")?;
        let scope = Rc::make_mut(scope);
        scope.macro_use_revision = Some(revision);
        scope.revision = revision;
        Ok(())
    }

    fn local_macro(&self, path: &syn::Path) -> Result<Option<MacroRulesDefinition>> {
        if path.leading_colon.is_some() || path.segments.len() != 1 {
            return Ok(None);
        }
        let Some(segment) = path.segments.first() else {
            return Ok(None);
        };
        let name = segment.ident.to_string();
        if self.macro_name_may_be_directly_imported(&name) {
            return Ok(None);
        }
        for scope in self.macro_scopes.iter().rev() {
            if let Some(binding) = scope.definitions.get(&name) {
                return match binding {
                    MacroBinding::Known {
                        definition,
                        revision,
                    } if scope
                        .macro_use_revision
                        .is_none_or(|macro_use_revision| *revision > macro_use_revision) =>
                    {
                        Ok(Some(definition.parse()?))
                    }
                    MacroBinding::Known { .. } => Ok(None),
                    MacroBinding::Ambiguous => Err(OpaqueExpansion::new(format!(
                        "multiple potentially active local macro_rules definitions are named `{name}`"
                    ))
                    .into()),
                };
            }
            if scope.macro_use_revision.is_some() {
                return Ok(None);
            }
            if let Some(definition) = scope.exported_definitions.get(&name) {
                return Ok(Some(definition.parse()?));
            }
        }
        Ok(None)
    }

    fn macro_name_may_be_imported(&self, name: &str) -> bool {
        self.macro_scopes.iter().rev().any(|scope| {
            scope.wildcard_import
                || scope.macro_use_revision.is_some()
                || scope.macro_use_prelude_candidate
                || scope.imported_names.contains(name)
        })
    }

    fn macro_name_may_be_directly_imported(&self, name: &str) -> bool {
        self.macro_scopes
            .iter()
            .rev()
            .any(|scope| scope.wildcard_import || scope.imported_names.contains(name))
    }

    fn expand_macro(&mut self, mac: &syn::Macro) -> Result<()> {
        let name = rust_path_display(&mac.path);
        let definition = self.local_macro(&mac.path)?.ok_or_else(|| {
            anyhow::Error::new(OpaqueExpansion::new(format!(
                "macro `{name}` is imported, procedural, built-in, or outside the statically known local scope"
            )))
        })?;
        let remaining_tokens = self.budgets.enter()?;
        let result = (|| {
            let (expanded, token_count) =
                definition.expand(mac.tokens.clone(), &name, remaining_tokens)?;
            self.budgets.note_expanded_tokens(token_count)?;
            let statements = syn::Block::parse_within.parse2(expanded).map_err(|error| {
                anyhow::Error::new(OpaqueExpansion::new(format!(
                    "local macro `{name}` expansion is not a statically parseable item or statement sequence: {error}"
                )))
            })?;
            for statement in &statements {
                self.visit_stmt(statement);
                if self.error.is_some() {
                    break;
                }
            }
            Ok(())
        })();
        self.budgets.leave();
        result
    }
}

impl<'ast> Visit<'ast> for ProcMacroModuleCollector<'_> {
    fn visit_stmt(&mut self, statement: &'ast syn::Stmt) {
        if self.error.is_some() {
            return;
        }
        let attributes = match statement {
            syn::Stmt::Local(local) => Some(local.attrs.as_slice()),
            syn::Stmt::Item(item) => item_attributes(item),
            syn::Stmt::Macro(statement_macro) => Some(statement_macro.attrs.as_slice()),
            syn::Stmt::Expr(expression, _) => expression_attributes(expression),
        };
        match attributes.map(module_attrs_are_definitely_disabled) {
            Some(Ok(true)) => return,
            Some(Err(error)) => {
                self.error = Some(error);
                return;
            }
            Some(Ok(false)) | None => {}
        }
        syn::visit::visit_stmt(self, statement);
    }

    fn visit_item(&mut self, item: &'ast syn::Item) {
        if self.error.is_some() {
            return;
        }
        if matches!(item, syn::Item::Verbatim(_)) {
            self.error = Some(
                OpaqueExpansion::new(
                    "unsupported Rust item syntax may emit modules and cannot be traversed statically",
                )
                .into(),
            );
            return;
        }
        match item_attributes(item).map(module_attrs_are_definitely_disabled) {
            Some(Ok(true)) => return,
            Some(Err(error)) => {
                self.error = Some(error);
                return;
            }
            Some(Ok(false)) | None => {}
        }
        if let Some(attributes) = item_attributes(item) {
            if let Err(error) = validate_proc_macro_attributes(attributes, |name| {
                self.macro_name_may_be_imported(name)
            }) {
                self.error = Some(error);
                return;
            }
        }
        syn::visit::visit_item(self, item);
    }

    fn visit_item_mod(&mut self, module: &'ast syn::ItemMod) {
        if self.error.is_none() {
            let result = self.collect_module(module).and_then(|()| {
                if has_attribute(&module.attrs, "macro_use") {
                    self.note_macro_use_module()?;
                }
                Ok(())
            });
            if let Err(error) = result {
                self.error = Some(error);
            }
        }
    }

    fn visit_item_macro(&mut self, item: &'ast syn::ItemMacro) {
        if self.error.is_some() {
            return;
        }
        let result = if item.mac.path.is_ident("macro_rules") && item.ident.is_some() {
            self.define_macro(item)
        } else {
            self.expand_macro(&item.mac)
        };
        if let Err(error) = result {
            self.error = Some(error);
        }
    }

    fn visit_impl_item(&mut self, item: &'ast syn::ImplItem) {
        if self.validate_associated_item_attributes(
            impl_item_attributes(item),
            matches!(item, syn::ImplItem::Verbatim(_)),
        ) {
            syn::visit::visit_impl_item(self, item);
        }
    }

    fn visit_trait_item(&mut self, item: &'ast syn::TraitItem) {
        if self.validate_associated_item_attributes(
            trait_item_attributes(item),
            matches!(item, syn::TraitItem::Verbatim(_)),
        ) {
            syn::visit::visit_trait_item(self, item);
        }
    }

    fn visit_foreign_item(&mut self, item: &'ast syn::ForeignItem) {
        if self.validate_associated_item_attributes(
            foreign_item_attributes(item),
            matches!(item, syn::ForeignItem::Verbatim(_)),
        ) {
            syn::visit::visit_foreign_item(self, item);
        }
    }

    fn visit_macro(&mut self, mac: &'ast syn::Macro) {
        if self.error.is_none() {
            if let Err(error) = self.expand_macro(mac) {
                self.error = Some(error);
            }
        }
    }

    fn visit_block(&mut self, block: &'ast syn::Block) {
        if self.error.is_some() {
            return;
        }
        let revision = match self.budgets.next_scope_revision() {
            Ok(revision) => revision,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let scope = match MacroScope::for_statements(&block.stmts, revision) {
            Ok(scope) => scope,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        self.macro_scopes.push(Rc::new(scope));
        for statement in &block.stmts {
            self.visit_stmt(statement);
            if self.error.is_some() {
                break;
            }
        }
        self.macro_scopes.pop();
    }
}

#[derive(Clone)]
struct DeferredMacroRulesDefinition {
    tokens: proc_macro2::TokenStream,
    edition: MacroRulesEdition,
}

impl DeferredMacroRulesDefinition {
    fn parse(&self) -> Result<MacroRulesDefinition> {
        MacroRulesDefinition::parse(self.tokens.clone(), self.edition)
    }
}

#[derive(Clone, Default)]
pub(in crate::scan) struct MacroScope {
    revision: usize,
    definitions: Rc<BTreeMap<String, MacroBinding>>,
    exported_definitions: Rc<BTreeMap<String, DeferredMacroRulesDefinition>>,
    imported_names: BTreeSet<String>,
    wildcard_import: bool,
    macro_use_revision: Option<usize>,
    macro_use_prelude_candidate: bool,
}

#[derive(Clone)]
enum MacroBinding {
    Known {
        definition: DeferredMacroRulesDefinition,
        revision: usize,
    },
    Ambiguous,
}

impl MacroScope {
    fn for_child_module(&self) -> Rc<Self> {
        Rc::new(Self {
            revision: self.revision,
            definitions: self.definitions.clone(),
            exported_definitions: Rc::default(),
            imported_names: BTreeSet::new(),
            wildcard_import: false,
            macro_use_revision: self.macro_use_revision,
            macro_use_prelude_candidate: self.macro_use_prelude_candidate,
        })
    }

    pub(super) fn affects_child_macro_resolution(&self) -> bool {
        !self.definitions.is_empty()
            || self.macro_use_revision.is_some()
            || self.macro_use_prelude_candidate
    }

    fn for_items(items: &[syn::Item], revision: usize) -> Result<Self> {
        let mut scope = Self {
            revision,
            ..Self::default()
        };
        for item in items {
            scope.note_item_imports(item)?;
        }
        Ok(scope)
    }

    fn for_statements(statements: &[syn::Stmt], revision: usize) -> Result<Self> {
        let mut scope = Self {
            revision,
            ..Self::default()
        };
        for statement in statements {
            if let syn::Stmt::Item(item) = statement {
                scope.note_item_imports(item)?;
            }
        }
        Ok(scope)
    }

    fn note_item_imports(&mut self, item: &syn::Item) -> Result<()> {
        if item_attributes(item)
            .map(module_attrs_are_definitely_disabled)
            .transpose()?
            .unwrap_or(false)
        {
            return Ok(());
        }
        if let syn::Item::Use(item) = item {
            collect_use_tree(
                &item.tree,
                None,
                &mut self.imported_names,
                &mut self.wildcard_import,
            );
        } else if matches!(item, syn::Item::ExternCrate(_))
            && item_attributes(item)
                .is_some_and(|attributes| has_attribute(attributes, "macro_use"))
        {
            self.macro_use_prelude_candidate = true;
        }
        Ok(())
    }
}

fn collect_use_tree(
    tree: &syn::UseTree,
    prefix: Option<&syn::Ident>,
    imported_names: &mut BTreeSet<String>,
    wildcard_import: &mut bool,
) {
    match tree {
        syn::UseTree::Path(path) => collect_use_tree(
            &path.tree,
            Some(&path.ident),
            imported_names,
            wildcard_import,
        ),
        syn::UseTree::Name(name) => {
            let imported = if name.ident == "self" {
                prefix.unwrap_or(&name.ident)
            } else {
                &name.ident
            };
            imported_names.insert(imported.to_string());
        }
        syn::UseTree::Rename(rename) if rename.rename != "_" => {
            imported_names.insert(rename.rename.to_string());
        }
        syn::UseTree::Rename(_) => {}
        syn::UseTree::Glob(_) => *wildcard_import = true,
        syn::UseTree::Group(group) => {
            for child in &group.items {
                collect_use_tree(child, prefix, imported_names, wildcard_import);
            }
        }
    }
}

fn has_attribute(attributes: &[syn::Attribute], name: &str) -> bool {
    attributes
        .iter()
        .any(|attribute| attribute.path().is_ident(name))
}

fn reject_local_inner_macros(attributes: &[syn::Attribute]) -> Result<()> {
    if attributes.iter().any(|attribute| {
        attribute.path().is_ident("macro_export") && matches!(attribute.meta, syn::Meta::List(_))
    }) {
        return Err(OpaqueExpansion::new(
            "#[macro_export(local_inner_macros)] hygiene cannot be reproduced statically",
        )
        .into());
    }
    Ok(())
}
