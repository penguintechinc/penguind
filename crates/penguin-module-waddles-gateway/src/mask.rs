//! Secret redaction for the one place a credential could otherwise leak
//! into command output: a freshly minted or rotated Community Access Token
//! (`token create` / `token rotate` — see `crate::commands`). Byte-for-byte
//! identical behaviour to `penguin_module_squawk::mask::mask_secret`; see
//! that module's doc for why this crate owns a small local copy rather than
//! pulling in a shared crate for one pure function.

/// Renders `value` as a non-reversible hint, never the value itself: empty
/// stays empty, four characters or fewer become `"****"`, and anything
/// longer becomes `"****"` plus its last four characters.
pub fn mask_secret(value: &str) -> String {
    if value.is_empty() {
        return String::new();
    }
    if value.chars().count() <= 4 {
        return "****".to_string();
    }

    // Byte index of the 4th-from-last character, found via `char_indices`
    // so a multibyte boundary can never split a character mid-way.
    let mut boundary = value.len();
    let mut seen = 0;
    for (index, _) in value.char_indices().rev() {
        boundary = index;
        seen += 1;
        if seen == 4 {
            break;
        }
    }

    let mut masked = String::with_capacity(4 + (value.len() - boundary));
    masked.push_str("****");
    masked.push_str(&value[boundary..]);
    masked
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_the_shared_masking_rules() {
        assert_eq!(mask_secret(""), "");
        assert_eq!(mask_secret("a"), "****");
        assert_eq!(mask_secret("abcd"), "****");
        assert_eq!(mask_secret("abcde"), "****bcde");
        assert_eq!(mask_secret("wdl_c_supersecrettoken"), "****oken");
    }

    #[test]
    fn is_char_boundary_safe_on_multibyte_input() {
        assert_eq!(mask_secret("αβγδεζ"), "****γδεζ");
    }
}
