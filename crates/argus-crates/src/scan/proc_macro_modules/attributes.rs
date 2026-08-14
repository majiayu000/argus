use super::super::macro_expansion::OpaqueExpansion;
use super::*;

pub(super) fn expression_attributes(expression: &syn::Expr) -> Option<&[syn::Attribute]> {
    match expression {
        syn::Expr::Array(expression) => Some(&expression.attrs),
        syn::Expr::Assign(expression) => Some(&expression.attrs),
        syn::Expr::Async(expression) => Some(&expression.attrs),
        syn::Expr::Await(expression) => Some(&expression.attrs),
        syn::Expr::Binary(expression) => Some(&expression.attrs),
        syn::Expr::Block(expression) => Some(&expression.attrs),
        syn::Expr::Break(expression) => Some(&expression.attrs),
        syn::Expr::Call(expression) => Some(&expression.attrs),
        syn::Expr::Cast(expression) => Some(&expression.attrs),
        syn::Expr::Closure(expression) => Some(&expression.attrs),
        syn::Expr::Const(expression) => Some(&expression.attrs),
        syn::Expr::Continue(expression) => Some(&expression.attrs),
        syn::Expr::Field(expression) => Some(&expression.attrs),
        syn::Expr::ForLoop(expression) => Some(&expression.attrs),
        syn::Expr::Group(expression) => Some(&expression.attrs),
        syn::Expr::If(expression) => Some(&expression.attrs),
        syn::Expr::Index(expression) => Some(&expression.attrs),
        syn::Expr::Infer(expression) => Some(&expression.attrs),
        syn::Expr::Let(expression) => Some(&expression.attrs),
        syn::Expr::Lit(expression) => Some(&expression.attrs),
        syn::Expr::Loop(expression) => Some(&expression.attrs),
        syn::Expr::Macro(expression) => Some(&expression.attrs),
        syn::Expr::Match(expression) => Some(&expression.attrs),
        syn::Expr::MethodCall(expression) => Some(&expression.attrs),
        syn::Expr::Paren(expression) => Some(&expression.attrs),
        syn::Expr::Path(expression) => Some(&expression.attrs),
        syn::Expr::Range(expression) => Some(&expression.attrs),
        syn::Expr::RawAddr(expression) => Some(&expression.attrs),
        syn::Expr::Reference(expression) => Some(&expression.attrs),
        syn::Expr::Repeat(expression) => Some(&expression.attrs),
        syn::Expr::Return(expression) => Some(&expression.attrs),
        syn::Expr::Struct(expression) => Some(&expression.attrs),
        syn::Expr::Try(expression) => Some(&expression.attrs),
        syn::Expr::TryBlock(expression) => Some(&expression.attrs),
        syn::Expr::Tuple(expression) => Some(&expression.attrs),
        syn::Expr::Unary(expression) => Some(&expression.attrs),
        syn::Expr::Unsafe(expression) => Some(&expression.attrs),
        syn::Expr::While(expression) => Some(&expression.attrs),
        syn::Expr::Yield(expression) => Some(&expression.attrs),
        syn::Expr::Verbatim(_) => None,
        _ => None,
    }
}

pub(super) fn validate_proc_macro_attributes(
    attributes: &[syn::Attribute],
    macro_name_may_be_imported: impl Fn(&str) -> bool,
) -> Result<()> {
    for attribute in attributes {
        validate_attribute_meta(&attribute.meta, 0, &macro_name_may_be_imported)?;
    }
    Ok(())
}

fn validate_attribute_meta(
    meta: &syn::Meta,
    depth: usize,
    macro_name_may_be_imported: &impl Fn(&str) -> bool,
) -> Result<()> {
    if depth > MAX_PROC_MACRO_META_DEPTH {
        anyhow::bail!("proc-macro attribute nesting exceeds {MAX_PROC_MACRO_META_DEPTH} levels");
    }
    let path = meta.path();
    let first = path
        .segments
        .first()
        .map(|segment| segment.ident.to_string());
    if matches!(first.as_deref(), Some("clippy" | "diagnostic" | "rustfmt")) {
        return Ok(());
    }
    let name = rust_path_display(path);
    if name == "unsafe" {
        let syn::Meta::List(list) = meta else {
            anyhow::bail!("unsafe attribute wrapper must contain an attribute");
        };
        let nested = syn::parse2::<syn::Meta>(list.tokens.clone())?;
        return validate_attribute_meta(&nested, depth + 1, macro_name_may_be_imported);
    }
    if name == "cfg_attr" {
        let syn::Meta::List(list) = meta else {
            anyhow::bail!("cfg_attr must contain arguments");
        };
        let metas = parse_cfg_list(list)?;
        let mut metas = metas.iter();
        let condition = metas.next().context("cfg_attr has no condition")?;
        if eval_cfg_meta(condition)? != CfgEval::False {
            for nested in metas {
                validate_attribute_meta(nested, depth + 1, macro_name_may_be_imported)?;
            }
        }
        return Ok(());
    }
    if name == "derive" {
        let syn::Meta::List(list) = meta else {
            anyhow::bail!("derive must contain arguments");
        };
        let derives = list.parse_args_with(
            syn::punctuated::Punctuated::<syn::Path, syn::Token![,]>::parse_terminated,
        )?;
        for derive in derives {
            let derive_name = rust_path_display(&derive);
            let is_builtin = matches!(
                derive_name.as_str(),
                "Clone"
                    | "Copy"
                    | "Debug"
                    | "Default"
                    | "Eq"
                    | "Hash"
                    | "Ord"
                    | "PartialEq"
                    | "PartialOrd"
            );
            if !is_builtin || macro_name_may_be_imported(&derive_name) {
                return Err(OpaqueExpansion::new(format!(
                    "derive macro `{derive_name}` may emit modules and cannot be expanded statically"
                ))
                .into());
            }
        }
        return Ok(());
    }
    if is_inert_or_builtin_attribute(&name) && !macro_name_may_be_imported(&name) {
        return Ok(());
    }
    Err(OpaqueExpansion::new(format!(
        "attribute macro `{name}` may emit modules and cannot be expanded statically"
    ))
    .into())
}

fn is_inert_or_builtin_attribute(name: &str) -> bool {
    matches!(
        name,
        "allow"
            | "alloc_error_handler"
            | "automatically_derived"
            | "bench"
            | "cfg"
            | "cold"
            | "crate_name"
            | "crate_type"
            | "deny"
            | "deprecated"
            | "debugger_visualizer"
            | "doc"
            | "export_name"
            | "expect"
            | "feature"
            | "forbid"
            | "global_allocator"
            | "inline"
            | "instruction_set"
            | "ignore"
            | "link"
            | "link_name"
            | "link_ordinal"
            | "link_section"
            | "macro_export"
            | "macro_use"
            | "must_use"
            | "naked"
            | "no_builtins"
            | "no_implicit_prelude"
            | "no_link"
            | "no_main"
            | "no_mangle"
            | "no_std"
            | "non_exhaustive"
            | "panic_handler"
            | "path"
            | "proc_macro"
            | "proc_macro_attribute"
            | "proc_macro_derive"
            | "recursion_limit"
            | "repr"
            | "should_panic"
            | "target_feature"
            | "test"
            | "track_caller"
            | "type_length_limit"
            | "used"
            | "warn"
            | "windows_subsystem"
            | "collapse_debuginfo"
    )
}
