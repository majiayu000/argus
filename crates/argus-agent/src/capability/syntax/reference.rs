use super::ScriptLanguage;

pub(super) fn executable_reference(raw: &str, language: ScriptLanguage) -> Option<String> {
    if language == ScriptLanguage::Bash {
        return (raw.contains('$') || raw.trim_start().starts_with('@')).then(|| raw.to_string());
    }
    let chars: Vec<char> = raw.chars().collect();
    let mut output = String::new();
    let mut index = 0;
    while index < chars.len() {
        let quote = chars[index];
        if matches!(quote, '\'' | '"') {
            index += 1;
            while index < chars.len() {
                if chars[index] == '\\' {
                    index += 2;
                } else if chars[index] == quote {
                    index += 1;
                    break;
                } else {
                    index += 1;
                }
            }
            continue;
        }
        if quote == '`' {
            index += 1;
            while index < chars.len() && chars[index] != '`' {
                if chars[index] == '$' && chars.get(index + 1) == Some(&'{') {
                    index += 2;
                    while index < chars.len() && chars[index] != '}' {
                        output.push(chars[index]);
                        index += 1;
                    }
                } else {
                    index += 1;
                }
            }
            index += usize::from(index < chars.len());
            continue;
        }
        output.push(chars[index]);
        index += 1;
    }
    (!output.trim().is_empty()).then_some(output)
}
