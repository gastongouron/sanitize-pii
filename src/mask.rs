use crate::detector::PiiKind;

/// Mask a matched PII string based on its kind.
pub fn mask(value: &str, kind: &PiiKind) -> String {
    match kind {
        PiiKind::Email => mask_email(value),
        PiiKind::CreditCard => mask_credit_card(value),
        PiiKind::Phone => mask_phone(value),
        PiiKind::IpV4 => mask_ipv4(value),
        PiiKind::IpV6 => "***:***:***:***".to_string(),
        PiiKind::ApiKey(_) | PiiKind::Custom(_) => mask_generic(value),
    }
}

fn mask_email(value: &str) -> String {
    let Some((local, domain)) = value.split_once('@') else {
        return mask_generic(value);
    };

    let masked_local = if local.len() <= 1 {
        "*".to_string()
    } else {
        format!("{}***", &local[..1])
    };

    format!(
        "{masked_local}@***.{}",
        domain.rsplit('.').next().unwrap_or("***")
    )
}

fn mask_credit_card(value: &str) -> String {
    let digits: String = value.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() >= 8 {
        let first4 = &digits[..4];
        let last4 = &digits[digits.len() - 4..];
        format!("{first4}-****-****-{last4}")
    } else {
        mask_generic(value)
    }
}

fn mask_phone(value: &str) -> String {
    let chars: Vec<char> = value.chars().collect();
    if chars.len() <= 4 {
        return "****".to_string();
    }
    let visible = 2;
    let masked: String = chars
        .iter()
        .enumerate()
        .map(|(i, &c)| {
            if i >= chars.len() - visible {
                c
            } else if c.is_ascii_digit() {
                '*'
            } else {
                c
            }
        })
        .collect();
    masked
}

fn mask_ipv4(value: &str) -> String {
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() == 4 {
        format!("{}.***.***.{}", parts[0], parts[3])
    } else {
        mask_generic(value)
    }
}

fn mask_generic(value: &str) -> String {
    if value.len() <= 4 {
        return "****".to_string();
    }
    let prefix: String = value.chars().take(4).collect();
    let stars = "*".repeat(value.len().saturating_sub(4).min(20));
    format!("{prefix}{stars}")
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- mask() dispatch ---

    #[test]
    fn mask_dispatches_email() {
        assert_eq!(mask("alice@example.com", &PiiKind::Email), "a***@***.com");
    }

    #[test]
    fn mask_dispatches_credit_card() {
        assert_eq!(
            mask("4111111111111111", &PiiKind::CreditCard),
            "4111-****-****-1111"
        );
    }

    #[test]
    fn mask_dispatches_phone() {
        let result = mask("0612345678", &PiiKind::Phone);
        assert!(result.contains('*'));
        assert!(result.ends_with("78"));
    }

    #[test]
    fn mask_dispatches_ipv4() {
        assert_eq!(mask("10.0.0.1", &PiiKind::IpV4), "10.***.***.1");
    }

    #[test]
    fn mask_dispatches_ipv6() {
        assert_eq!(
            mask("2001:0db8:85a3:0000:0000:8a2e:0370:7334", &PiiKind::IpV6),
            "***:***:***:***"
        );
    }

    #[test]
    fn mask_dispatches_api_key() {
        let result = mask("sk_live_abc123def456", &PiiKind::ApiKey("stripe".into()));
        assert!(result.starts_with("sk_l"));
        assert!(result.contains('*'));
    }

    #[test]
    fn mask_dispatches_custom() {
        let result = mask("123-45-6789", &PiiKind::Custom("ssn".into()));
        assert!(result.contains('*'));
    }

    // --- Email ---

    #[test]
    fn mask_email_standard() {
        assert_eq!(mask_email("alice@example.com"), "a***@***.com");
    }

    #[test]
    fn mask_email_short_local() {
        assert_eq!(mask_email("a@b.co"), "*@***.co");
    }

    #[test]
    fn mask_email_no_at() {
        // Falls back to mask_generic
        let result = mask_email("notanemail");
        assert!(result.contains('*'));
    }

    // --- Credit Card ---

    #[test]
    fn mask_credit_card_spaced() {
        assert_eq!(
            mask_credit_card("4111 1111 1111 1111"),
            "4111-****-****-1111"
        );
    }

    #[test]
    fn mask_credit_card_dashed() {
        assert_eq!(
            mask_credit_card("4111-1111-1111-1111"),
            "4111-****-****-1111"
        );
    }

    #[test]
    fn mask_credit_card_few_digits() {
        // Fewer than 8 digits falls back to generic
        let result = mask_credit_card("1234");
        assert_eq!(result, "****");
    }

    // --- Phone ---

    #[test]
    fn mask_phone_standard() {
        let result = mask_phone("+33612345678");
        assert!(result.ends_with("78"));
        assert!(result.contains('*'));
    }

    #[test]
    fn mask_phone_short() {
        assert_eq!(mask_phone("1234"), "****");
    }

    #[test]
    fn mask_phone_with_separators() {
        let result = mask_phone("06-12-34-56-78");
        // Separators preserved, digits masked except last 2 chars
        assert!(result.contains('-'));
        assert!(result.ends_with("78"));
    }

    // --- IPv4 ---

    #[test]
    fn mask_ipv4_standard() {
        assert_eq!(mask_ipv4("192.168.1.42"), "192.***.***.42");
    }

    #[test]
    fn mask_ipv4_not_four_parts() {
        // Falls back to generic
        let result = mask_ipv4("192.168.1");
        assert!(result.contains('*'));
    }

    // --- Generic ---

    #[test]
    fn mask_generic_short() {
        assert_eq!(mask_generic("abc"), "****");
    }

    #[test]
    fn mask_generic_exactly_four() {
        assert_eq!(mask_generic("abcd"), "****");
    }

    #[test]
    fn mask_generic_five() {
        assert_eq!(mask_generic("abcde"), "abcd*");
    }

    #[test]
    fn mask_generic_long() {
        assert_eq!(mask_generic("sk_live_abc123def456"), "sk_l****************");
    }

    #[test]
    fn mask_generic_very_long() {
        // Stars capped at 20
        let input = "a".repeat(30);
        let result = mask_generic(&input);
        assert!(result.starts_with("aaaa"));
        assert_eq!(result.len(), 24); // 4 prefix + 20 stars
    }
}
