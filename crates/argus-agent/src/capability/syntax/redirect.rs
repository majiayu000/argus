use super::StaticValue;

/// A shell redirection kept as typed provenance rather than a bare target, so
/// consumers can tell `cmd > target` (a write) from `cmd < target` (file
/// content entering the command on a descriptor).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(in crate::capability) struct Redirect {
    pub fd: Option<u32>,
    pub direction: RedirectDirection,
    pub target: StaticValue,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(in crate::capability) enum RedirectDirection {
    Input,
    Output,
}

impl Redirect {
    /// True when this redirection feeds file content in on stdin, which is the
    /// only input descriptor a client such as `curl --data-binary @-` consumes.
    pub fn is_stdin_input(&self) -> bool {
        self.direction == RedirectDirection::Input && matches!(self.fd, None | Some(0))
    }

    /// True when this redirection writes to its target.
    pub fn is_write(&self) -> bool {
        self.direction == RedirectDirection::Output
    }
}

/// Classify a redirection operator.
///
/// Unknown operators fall back to `Output` so a redirection this parser does
/// not model keeps its existing write-detection behavior instead of silently
/// dropping out of the write surface.
pub(in crate::capability) fn redirect_direction(operator: &str) -> RedirectDirection {
    let operator = operator.trim();
    let symbols = operator.trim_start_matches(|character: char| character.is_ascii_digit());
    match symbols {
        "<" | "<<" | "<<<" | "<&" => RedirectDirection::Input,
        _ => RedirectDirection::Output,
    }
}

/// Extract an explicit descriptor number from a redirection operator prefix
/// (`2>`, `0<`). Returns `None` when the operator leaves the descriptor
/// implicit, which the direction then determines.
pub(in crate::capability) fn redirect_fd(operator: &str) -> Option<u32> {
    let digits: String = operator
        .trim()
        .chars()
        .take_while(|character| character.is_ascii_digit())
        .collect();
    if digits.is_empty() {
        return None;
    }
    digits.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn input_operators_are_typed_as_input() {
        for operator in ["<", "0<", "<<", "<<<"] {
            assert_eq!(
                redirect_direction(operator),
                RedirectDirection::Input,
                "{operator}"
            );
        }
    }

    #[test]
    fn output_and_unknown_operators_stay_writes() {
        for operator in [">", ">>", "2>", "&>", "<>", "?!"] {
            assert_eq!(
                redirect_direction(operator),
                RedirectDirection::Output,
                "{operator}"
            );
        }
    }

    #[test]
    fn explicit_descriptor_is_extracted() {
        assert_eq!(redirect_fd("2>"), Some(2));
        assert_eq!(redirect_fd("0<"), Some(0));
        assert_eq!(redirect_fd("<"), None);
        assert_eq!(redirect_fd(">"), None);
    }

    #[test]
    fn only_stdin_input_counts_as_consumed_input() {
        let target = StaticValue {
            raw: "/home/demo/.aws/credentials".to_string(),
            resolved: Some("/home/demo/.aws/credentials".to_string()),
            executable_reference: None,
            executable_reference_fragments: Vec::new(),
            shell_argument: super::super::ShellArgument::NotShell,
        };
        let stdin = Redirect {
            fd: None,
            direction: RedirectDirection::Input,
            target: target.clone(),
        };
        assert!(stdin.is_stdin_input());
        assert!(!stdin.is_write());

        let other_fd = Redirect {
            fd: Some(3),
            direction: RedirectDirection::Input,
            target: target.clone(),
        };
        assert!(!other_fd.is_stdin_input());

        let write = Redirect {
            fd: None,
            direction: RedirectDirection::Output,
            target,
        };
        assert!(!write.is_stdin_input());
        assert!(write.is_write());
    }
}
