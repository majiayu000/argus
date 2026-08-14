use super::*;
use anyhow::anyhow;
use proc_macro2::Group;

const MAX_TRANSCRIBE_DEPTH: usize = 32;

pub(super) fn transcribe_bounded(
    tokens: &TokenStream,
    bindings: &Bindings,
    max_output_tokens: usize,
) -> Result<(TokenStream, usize)> {
    let mut output_budget = OutputBudget::new(max_output_tokens);
    let tokens = transcribe(tokens, bindings, None, 0, &mut output_budget)?;
    Ok((tokens, output_budget.emitted))
}

fn transcribe(
    tokens: &TokenStream,
    bindings: &Bindings,
    repetition_index: Option<usize>,
    depth: usize,
    output_budget: &mut OutputBudget,
) -> Result<TokenStream> {
    if depth > MAX_TRANSCRIBE_DEPTH {
        return opaque(format!(
            "local macro transcription exceeds {MAX_TRANSCRIBE_DEPTH} levels"
        ));
    }
    let tokens = token_vec(tokens.clone());
    let mut output = TokenStream::new();
    let mut at = 0;
    while at < tokens.len() {
        if punct_at(&tokens, at, '$') {
            match tokens.get(at + 1) {
                Some(TokenTree::Ident(name)) => {
                    let name = name.to_string();
                    let captures = bindings.get(&name).ok_or_else(|| {
                        anyhow!(OpaqueExpansion::new(format!(
                            "macro transcriber references unknown `${name}`"
                        )))
                    })?;
                    let selected = match (repetition_index, captures.repeated) {
                        (Some(index), true) => captures.values.get(index),
                        (None, false) | (Some(_), false) => captures.values.first(),
                        (None, true) => None,
                    }
                    .ok_or_else(|| {
                        anyhow!(OpaqueExpansion::new(format!(
                            "macro transcriber cannot select `${name}` repetition"
                        )))
                    })?;
                    output_budget.note_stream(selected)?;
                    output.extend(selected.clone());
                    at += 2;
                    continue;
                }
                Some(TokenTree::Group(group)) => {
                    let (separator, kind, consumed) = parse_repeat_suffix(&tokens, at + 2)?;
                    let names = referenced_names(group.stream(), 0)?;
                    let mut repeated_count = None;
                    for name in names {
                        let captures = bindings.get(&name).ok_or_else(|| {
                            anyhow!(OpaqueExpansion::new(format!(
                                "macro repetition references unknown `${name}`"
                            )))
                        })?;
                        if captures.repeated {
                            match repeated_count {
                                Some(count) if count != captures.values.len() => {
                                    return opaque("macro repetition capture lengths disagree")
                                }
                                None => repeated_count = Some(captures.values.len()),
                                Some(_) => {}
                            }
                        }
                    }
                    let count = repeated_count.ok_or_else(|| {
                        anyhow!(OpaqueExpansion::new(
                            "macro transcriber repetition has no repeated metavariable"
                        ))
                    })?;
                    if matches!(kind, RepeatKind::OneOrMore) && count == 0 {
                        return opaque("one-or-more macro transcription has no captures");
                    }
                    if matches!(kind, RepeatKind::ZeroOrOne) && count > 1 {
                        return opaque("optional macro transcription has multiple captures");
                    }
                    for index in 0..count {
                        if index > 0 {
                            if let Some(separator) = &separator {
                                output_budget.note_token()?;
                                output.extend(std::iter::once(separator.clone()));
                            }
                        }
                        output.extend(transcribe(
                            &group.stream(),
                            bindings,
                            Some(index),
                            depth + 1,
                            output_budget,
                        )?);
                    }
                    at += 2 + consumed;
                    continue;
                }
                _ => return opaque("unsupported `$` form in macro transcriber"),
            }
        }
        match &tokens[at] {
            TokenTree::Group(group) => {
                let mut expanded = Group::new(
                    group.delimiter(),
                    transcribe(
                        &group.stream(),
                        bindings,
                        repetition_index,
                        depth + 1,
                        output_budget,
                    )?,
                );
                expanded.set_span(group.span());
                output_budget.note_token()?;
                output.extend(std::iter::once(TokenTree::Group(expanded)));
            }
            token => {
                output_budget.note_token()?;
                output.extend(std::iter::once(token.clone()));
            }
        }
        at += 1;
    }
    Ok(output)
}

struct OutputBudget {
    remaining: usize,
    emitted: usize,
}

impl OutputBudget {
    fn new(max_tokens: usize) -> Self {
        Self {
            remaining: max_tokens,
            emitted: 0,
        }
    }

    fn note_token(&mut self) -> Result<()> {
        self.note_tokens(1)
    }

    fn note_stream(&mut self, tokens: &TokenStream) -> Result<()> {
        self.note_tokens(token_tree_count(tokens))
    }

    fn note_tokens(&mut self, count: usize) -> Result<()> {
        if count > self.remaining {
            return opaque("local macro expansion exceeds the shared output token budget");
        }
        self.remaining -= count;
        self.emitted += count;
        Ok(())
    }
}

fn referenced_names(tokens: TokenStream, depth: usize) -> Result<BTreeSet<String>> {
    if depth > MAX_TRANSCRIBE_DEPTH {
        return opaque("macro transcriber reference nesting is too deep");
    }
    let tokens = token_vec(tokens);
    let mut names = BTreeSet::new();
    let mut at = 0;
    while at < tokens.len() {
        if punct_at(&tokens, at, '$') {
            match tokens.get(at + 1) {
                Some(TokenTree::Ident(name)) => {
                    names.insert(name.to_string());
                    at += 2;
                    continue;
                }
                Some(TokenTree::Group(group)) => {
                    names.extend(referenced_names(group.stream(), depth + 1)?);
                }
                _ => return opaque("unsupported `$` reference in macro transcriber"),
            }
        } else if let TokenTree::Group(group) = &tokens[at] {
            names.extend(referenced_names(group.stream(), depth + 1)?);
        }
        at += 1;
    }
    Ok(names)
}
