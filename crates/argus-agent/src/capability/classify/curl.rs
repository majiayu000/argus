use super::super::syntax::{ShellArgument, StaticValue};
use std::ops::Range;

#[derive(Clone, Default)]
pub(super) struct CurlInput {
    file_sources: Vec<CurlFileSource>,
    reads_stdin: bool,
}

#[derive(Clone)]
struct CurlFileSource {
    value: String,
    raw_span: Option<Range<usize>>,
    scan_sensitive: bool,
    stdin_allowed: bool,
}

impl CurlInput {
    pub(super) fn file_sources(&self) -> impl Iterator<Item = &str> {
        self.file_sources
            .iter()
            .filter(|source| source.scan_sensitive)
            .map(|source| source.value.as_str())
    }

    pub(super) fn reads_stdin(&self) -> bool {
        self.reads_stdin
    }

    fn merge(&mut self, mut other: Self) {
        self.file_sources.append(&mut other.file_sources);
        self.reads_stdin |= other.reads_stdin;
    }

    fn add_source(&mut self, path: String, raw_span: Option<Range<usize>>, stdin_allowed: bool) {
        if path.is_empty() {
            return;
        }
        if stdin_allowed && path == "-" {
            self.reads_stdin = true;
        } else {
            self.file_sources.push(CurlFileSource {
                scan_sensitive: !path.contains(['\'', '"', '$']),
                value: path,
                raw_span,
                stdin_allowed,
            });
        }
    }

    fn add_reference_sources(&mut self, argument: &StaticValue) {
        let source_snapshot = self.file_sources.clone();
        for fragment in &argument.executable_reference_fragments {
            let matching_sources: Vec<usize> = source_snapshot
                .iter()
                .enumerate()
                .filter_map(|(index, source)| {
                    source
                        .raw_span
                        .as_ref()
                        .is_some_and(|span| {
                            ranges_overlap(span, fragment.start_byte..fragment.end_byte)
                        })
                        .then_some(index)
                })
                .collect();
            let referenced_source = !matching_sources.is_empty();
            for index in matching_sources {
                if let Some(source) = self.file_sources.get_mut(index) {
                    source.scan_sensitive = true;
                }
            }
            if referenced_source
                && !self
                    .file_sources
                    .iter()
                    .any(|source| source.value == fragment.resolved)
            {
                self.file_sources.push(CurlFileSource {
                    value: fragment.resolved.clone(),
                    raw_span: None,
                    scan_sensitive: true,
                    stdin_allowed: false,
                });
            }
            if referenced_source {
                if let Some(resolved) = fragment
                    .constant_resolved
                    .as_ref()
                    .filter(|resolved| super::is_sensitive_path(resolved))
                {
                    if !self
                        .file_sources
                        .iter()
                        .any(|source| source.value == *resolved)
                    {
                        self.file_sources.push(CurlFileSource {
                            value: resolved.clone(),
                            raw_span: None,
                            scan_sensitive: true,
                            stdin_allowed: false,
                        });
                    }
                }
            }
            if referenced_source
                && fragment.constant_resolved.as_deref() == Some("-")
                && matching_source_allows_stdin(&source_snapshot, fragment)
            {
                self.reads_stdin = true;
            }
        }
    }
}

fn matching_source_allows_stdin(
    sources: &[CurlFileSource],
    fragment: &super::super::syntax::ExecutableReferenceFragment,
) -> bool {
    sources.iter().any(|source| {
        source.stdin_allowed
            && source
                .raw_span
                .as_ref()
                .is_some_and(|span| ranges_overlap(span, fragment.start_byte..fragment.end_byte))
    })
}

#[derive(Clone, Copy)]
enum InputOperand {
    Data,
    DataUrlencode,
    Form,
    Upload,
}

enum ShortOption<'a> {
    Input(InputOperand, Option<&'a str>),
    OtherValue(Option<&'a str>),
    Flags,
}

#[derive(Clone, Copy)]
struct ArgumentText<'a> {
    text: &'a str,
    raw_boundaries: Option<&'a [usize]>,
    raw_offset: Option<usize>,
}

impl<'a> ArgumentText<'a> {
    fn source_map(self, text_start: usize) -> SourceMap<'a> {
        SourceMap {
            raw_boundaries: self.raw_boundaries,
            raw_offset: self.raw_offset,
            text_start,
        }
    }
}

#[derive(Clone, Copy)]
struct SourceMap<'a> {
    raw_boundaries: Option<&'a [usize]>,
    raw_offset: Option<usize>,
    text_start: usize,
}

impl SourceMap<'_> {
    fn with_text_offset(self, offset: usize) -> Self {
        Self {
            text_start: self.text_start + offset,
            ..self
        }
    }

    fn raw_span(self, span: Range<usize>) -> Option<Range<usize>> {
        let start = self.text_start + span.start;
        let end = self.text_start + span.end;
        if let Some(boundaries) = self.raw_boundaries {
            return Some(*boundaries.get(start)?..*boundaries.get(end)?);
        }
        self.raw_offset.map(|offset| offset + start..offset + end)
    }
}

pub(super) fn curl_argument_inputs(arguments: &[StaticValue]) -> Vec<CurlInput> {
    let mut inputs = vec![CurlInput::default(); arguments.len()];
    let mut index = 0;
    while index < arguments.len() {
        let Some(value) = curl_argument_text(&arguments[index]) else {
            index += 1;
            continue;
        };
        let text = value.text;
        if text == "--" {
            break;
        }
        if let Some((kind, operand)) = long_input_option(text) {
            index += decode_operand(arguments, &mut inputs, index, value, kind, operand);
            continue;
        }
        if let Some(name) = text.strip_prefix("--") {
            index += if !name.contains('=') && long_option_takes_value(name) {
                2
            } else {
                1
            };
            continue;
        }
        match short_option(text) {
            Some(ShortOption::Input(kind, operand)) => {
                index += decode_operand(arguments, &mut inputs, index, value, kind, operand);
            }
            Some(ShortOption::OtherValue(operand)) => {
                index += usize::from(operand.is_none()) + 1;
            }
            Some(ShortOption::Flags) | None => index += 1,
        }
    }
    inputs
}

fn decode_operand(
    arguments: &[StaticValue],
    inputs: &mut [CurlInput],
    index: usize,
    value: ArgumentText<'_>,
    kind: InputOperand,
    attached: Option<&str>,
) -> usize {
    if let Some(operand) = attached {
        let operand_start = value.text.len().saturating_sub(operand.len());
        inputs[index] = curl_input(kind, operand, value.source_map(operand_start));
        inputs[index].add_reference_sources(&arguments[index]);
        return 1;
    }
    let Some(argument) = arguments.get(index.saturating_add(1)) else {
        return 1;
    };
    let Some(value) = curl_argument_text(argument) else {
        return 2;
    };
    inputs[index + 1] = curl_input(kind, value.text, value.source_map(0));
    inputs[index + 1].add_reference_sources(argument);
    2
}

fn long_input_option(value: &str) -> Option<(InputOperand, Option<&str>)> {
    let (name, operand) = value
        .split_once('=')
        .map_or((value, None), |(name, operand)| (name, Some(operand)));
    let kind = match name {
        "--data" | "--data-ascii" | "--data-binary" | "--json" => InputOperand::Data,
        "--data-urlencode" => InputOperand::DataUrlencode,
        "--form" => InputOperand::Form,
        "--upload-file" => InputOperand::Upload,
        _ => return None,
    };
    Some((kind, operand))
}

fn short_option(value: &str) -> Option<ShortOption<'_>> {
    let options = value.strip_prefix('-')?;
    if options.is_empty() || options.starts_with('-') {
        return None;
    }
    for (offset, option) in options.char_indices() {
        let operand = &options[offset + option.len_utf8()..];
        let operand = (!operand.is_empty()).then_some(operand);
        match option {
            'd' => return Some(ShortOption::Input(InputOperand::Data, operand)),
            'F' => return Some(ShortOption::Input(InputOperand::Form, operand)),
            'T' => return Some(ShortOption::Input(InputOperand::Upload, operand)),
            option if short_option_takes_value(option) => {
                return Some(ShortOption::OtherValue(operand));
            }
            option if short_flag(option) => {}
            _ => return Some(ShortOption::Flags),
        }
    }
    Some(ShortOption::Flags)
}

fn short_option_takes_value(option: char) -> bool {
    matches!(
        option,
        'A' | 'b'
            | 'c'
            | 'C'
            | 'D'
            | 'e'
            | 'E'
            | 'H'
            | 'K'
            | 'h'
            | 'm'
            | 'o'
            | 'P'
            | 'Q'
            | 'r'
            | 't'
            | 'u'
            | 'U'
            | 'w'
            | 'x'
            | 'X'
            | 'y'
            | 'Y'
            | 'z'
    )
}

fn short_flag(option: char) -> bool {
    matches!(
        option,
        'a' | 'B'
            | 'f'
            | 'g'
            | 'G'
            | 'i'
            | 'I'
            | 'j'
            | 'J'
            | 'k'
            | 'l'
            | 'L'
            | 'M'
            | 'n'
            | 'N'
            | 'O'
            | 'p'
            | 'q'
            | 'R'
            | 's'
            | 'S'
            | 'v'
            | 'V'
            | 'Z'
            | '0'
            | '1'
            | '2'
            | '3'
            | '4'
            | '6'
            | '9'
            | '#'
            | ':'
    )
}

// Value-taking long options from curl 8.7's complete `--help all` schema.
// Input-bearing options are decoded before this table; the rest are consumed
// solely to prevent an operand that begins with '-' from becoming a new option.
const LONG_VALUE_OPTIONS: &str = "\
abstract-unix-socket alt-svc aws-sigv4 cacert capath cert cert-type ciphers config \
connect-timeout connect-to continue-at cookie cookie-jar create-file-mode crlfile curves \
data data-ascii data-binary data-raw data-urlencode delegation dns-interface dns-ipv4-addr \
dns-ipv6-addr dns-servers doh-url dump-header egd-file engine etag-compare etag-save \
expect100-timeout form form-string ftp-account ftp-alternative-to-user ftp-method ftp-port \
ftp-ssl-ccc-mode happy-eyeballs-timeout-ms haproxy-clientip header help hostpubmd5 \
hostpubsha256 hsts interface ipfs-gateway json keepalive-time key key-type krb libcurl \
limit-rate local-port login-options mail-auth mail-from mail-rcpt max-filesize max-redirs \
max-time netrc-file noproxy oauth2-bearer output output-dir parallel-max pass pinnedpubkey \
proto proto-default proto-redir proxy preproxy proxy1.0 proxy-cacert proxy-capath proxy-cert proxy-cert-type \
proxy-ciphers proxy-crlfile proxy-header proxy-key proxy-key-type proxy-pass \
proxy-pinnedpubkey proxy-service-name proxy-tls13-ciphers proxy-tlsauthtype \
proxy-tlspassword proxy-tlsuser proxy-user pubkey quote random-file range rate referer \
request request-target resolve retry retry-delay retry-max-time sasl-authzid service-name \
socks4 socks4a socks5 socks5-gssapi-service socks5-hostname speed-limit speed-time stderr \
telnet-option tftp-blksize time-cond tls-max tls13-ciphers tlsauthtype tlspassword tlsuser \
trace trace-ascii trace-config unix-socket upload-file url url-query user user-agent \
variable write-out";

fn long_option_takes_value(option: &str) -> bool {
    LONG_VALUE_OPTIONS
        .split_ascii_whitespace()
        .any(|candidate| candidate == option)
}

fn curl_input(kind: InputOperand, operand: &str, source_map: SourceMap<'_>) -> CurlInput {
    match kind {
        InputOperand::Data => operand
            .strip_prefix('@')
            .map(|path| curl_path_input(path, source_map.with_text_offset(1), true))
            .unwrap_or_default(),
        InputOperand::DataUrlencode => curl_data_urlencode_input(operand, source_map),
        InputOperand::Form => curl_form_input(operand, source_map),
        InputOperand::Upload => curl_path_input(operand, source_map, true),
    }
}

fn curl_data_urlencode_input(operand: &str, source_map: SourceMap<'_>) -> CurlInput {
    if let Some(path) = operand.strip_prefix('@') {
        return curl_path_input(path, source_map.with_text_offset(1), true);
    }
    if operand.contains('=') {
        return CurlInput::default();
    }
    operand
        .split_once('@')
        .filter(|(name, _)| !name.is_empty())
        .map(|(name, path)| {
            curl_path_input(path, source_map.with_text_offset(name.len() + 1), true)
        })
        .unwrap_or_default()
}

fn curl_form_input(operand: &str, source_map: SourceMap<'_>) -> CurlInput {
    let Some(equal) = operand.find('=') else {
        return CurlInput::default();
    };
    let content_start = equal + 1;
    let content = &operand[content_start..];
    if content.starts_with('@') {
        let mut input = CurlInput::default();
        let mut cursor = content_start + 1;
        while cursor <= operand.len() {
            let (part, separator) = form_part_input(operand, cursor, Some(b','), true, source_map);
            input.merge(part);
            let Some(separator) = separator.filter(|index| operand.as_bytes()[*index] == b',')
            else {
                break;
            };
            cursor = separator + 1;
        }
        return input;
    }
    if content.starts_with('<') {
        return form_part_input(operand, content_start + 1, None, true, source_map).0;
    }
    form_part_input(operand, content_start, None, false, source_map).0
}

fn form_part_input(
    operand: &str,
    start: usize,
    endchar: Option<u8>,
    primary_is_source: bool,
    source_map: SourceMap<'_>,
) -> (CurlInput, Option<usize>) {
    let mut input = CurlInput::default();
    let primary = form_word(operand, start, endchar);
    if primary_is_source {
        input.add_source(primary.value, source_map.raw_span(primary.span), true);
    }
    let mut separator = primary.separator;
    while separator.is_some_and(|index| operand.as_bytes()[index] == b';') {
        let mut cursor = skip_ascii_space(operand, separator.unwrap_or(start) + 1);
        if has_prefix_ignore_ascii_case(&operand[cursor..], "headers=") {
            cursor += "headers=".len();
            if operand
                .as_bytes()
                .get(cursor)
                .is_some_and(|byte| matches!(byte, b'@' | b'<'))
            {
                cursor = skip_ascii_space(operand, cursor + 1);
                let header = form_word(operand, cursor, endchar);
                input.add_source(header.value, source_map.raw_span(header.span), false);
                separator = header.separator;
                continue;
            }
            cursor = skip_ascii_space(operand, cursor);
            separator = form_word(operand, cursor, endchar).separator;
            continue;
        }
        if has_prefix_ignore_ascii_case(&operand[cursor..], "filename=") {
            cursor = skip_ascii_space(operand, cursor + "filename=".len());
            separator = form_word(operand, cursor, endchar).separator;
            continue;
        }
        if has_prefix_ignore_ascii_case(&operand[cursor..], "encoder=") {
            cursor = skip_ascii_space(operand, cursor + "encoder=".len());
            separator = form_word(operand, cursor, endchar).separator;
            continue;
        }
        separator = form_word(operand, cursor, endchar).separator;
    }
    (input, separator)
}

struct FormWord {
    value: String,
    span: Range<usize>,
    separator: Option<usize>,
}

fn form_word(operand: &str, start: usize, endchar: Option<u8>) -> FormWord {
    let start = skip_ascii_space(operand, start);
    if operand.as_bytes().get(start) == Some(&b'"') {
        if let Some(end_quote) = closing_form_quote(operand, start + 1) {
            let separator = next_form_separator(operand, end_quote + 1, endchar);
            return FormWord {
                value: decode_quoted_form_word(&operand[start + 1..end_quote]),
                span: start + 1..end_quote,
                separator,
            };
        }
    }
    let separator = next_form_separator(operand, start, endchar);
    let end = trim_ascii_space_end(operand, start, separator.unwrap_or(operand.len()));
    FormWord {
        value: operand[start..end].to_string(),
        span: start..end,
        separator,
    }
}

fn closing_form_quote(operand: &str, mut index: usize) -> Option<usize> {
    let bytes = operand.as_bytes();
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes
                .get(index + 1)
                .is_some_and(|next| matches!(*next, b'\\' | b'"'))
        {
            index += 2;
        } else if bytes[index] == b'"' {
            return Some(index);
        } else {
            index += 1;
        }
    }
    None
}

fn decode_quoted_form_word(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut output = String::new();
    let mut chunk_start = 0;
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && bytes
                .get(index + 1)
                .is_some_and(|next| matches!(*next, b'\\' | b'"'))
        {
            output.push_str(&value[chunk_start..index]);
            output.push(bytes[index + 1] as char);
            index += 2;
            chunk_start = index;
        } else {
            index += 1;
        }
    }
    output.push_str(&value[chunk_start..]);
    output
}

fn next_form_separator(operand: &str, start: usize, endchar: Option<u8>) -> Option<usize> {
    operand.as_bytes()[start..]
        .iter()
        .position(|byte| *byte == b';' || endchar == Some(*byte))
        .map(|offset| start + offset)
}

fn skip_ascii_space(value: &str, mut index: usize) -> usize {
    while value
        .as_bytes()
        .get(index)
        .is_some_and(u8::is_ascii_whitespace)
    {
        index += 1;
    }
    index
}

fn trim_ascii_space_end(value: &str, start: usize, mut end: usize) -> usize {
    while end > start && value.as_bytes()[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    end
}

fn has_prefix_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .get(..prefix.len())
        .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
}

fn curl_path_input(path: &str, source_map: SourceMap<'_>, stdin_allowed: bool) -> CurlInput {
    let mut input = CurlInput::default();
    input.add_source(
        path.to_string(),
        source_map.raw_span(0..path.len()),
        stdin_allowed,
    );
    input
}

fn curl_argument_text(argument: &StaticValue) -> Option<ArgumentText<'_>> {
    match &argument.shell_argument {
        ShellArgument::Known(value) => Some(ArgumentText {
            text: &value.text,
            raw_boundaries: Some(&value.raw_boundaries),
            raw_offset: None,
        }),
        ShellArgument::Dynamic => None,
        ShellArgument::NotShell => {
            let text = argument
                .resolved
                .as_deref()
                .unwrap_or_else(|| trim_one_quote_pair(&argument.raw));
            Some(ArgumentText {
                text,
                raw_boundaries: None,
                raw_offset: argument.raw.find(text),
            })
        }
    }
}

fn trim_one_quote_pair(value: &str) -> &str {
    if value.len() >= 2 {
        let first = value.as_bytes()[0];
        let last = value.as_bytes()[value.len() - 1];
        if first == last && matches!(first, b'\'' | b'"') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

fn ranges_overlap(left: &Range<usize>, right: Range<usize>) -> bool {
    left.start < right.end && right.start < left.end
}
