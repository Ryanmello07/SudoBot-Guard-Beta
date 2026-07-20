#[derive(Debug, PartialEq, Eq)]
pub enum CodeShape {
    Totp,
    Yubikey,
}

/// TOTP codes are exactly 6 ASCII digits; YubiKey OTPs are exactly 44
/// alphanumeric (modhex) characters. Anything else isn't a recognizable code.
pub fn detect_code_shape(code: &str) -> Option<CodeShape> {
    if code.len() == 6 && code.chars().all(|c| c.is_ascii_digit()) {
        Some(CodeShape::Totp)
    } else if code.len() == 44 && code.chars().all(|c| c.is_ascii_alphanumeric()) {
        Some(CodeShape::Yubikey)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recognizes_six_digit_totp_code() {
        assert_eq!(detect_code_shape("123456"), Some(CodeShape::Totp));
    }

    #[test]
    fn recognizes_forty_four_char_yubikey_otp() {
        let otp = "c".repeat(44);
        assert_eq!(detect_code_shape(&otp), Some(CodeShape::Yubikey));
    }

    #[test]
    fn rejects_five_digit_code() {
        assert_eq!(detect_code_shape("12345"), None);
    }

    #[test]
    fn rejects_seven_digit_code() {
        assert_eq!(detect_code_shape("1234567"), None);
    }

    #[test]
    fn rejects_six_chars_with_a_letter() {
        assert_eq!(detect_code_shape("12345a"), None);
    }

    #[test]
    fn rejects_forty_three_char_string() {
        let s = "c".repeat(43);
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_forty_five_char_string() {
        let s = "c".repeat(45);
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_forty_four_chars_with_a_symbol() {
        let s = format!("{}!", "c".repeat(43));
        assert_eq!(detect_code_shape(&s), None);
    }

    #[test]
    fn rejects_empty_string() {
        assert_eq!(detect_code_shape(""), None);
    }
}
