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

    format!("{masked_local}@***.{}", domain.rsplit('.').next().unwrap_or("***"))
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

    #[test]
    fn mask_email_standard() {
        assert_eq!(mask_email("alice@example.com"), "a***@***.com");
    }

    #[test]
    fn mask_email_short_local() {
        assert_eq!(mask_email("a@b.co"), "*@***.co");
    }

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
    fn mask_ipv4_standard() {
        assert_eq!(mask_ipv4("192.168.1.42"), "192.***.***.42");
    }

    #[test]
    fn mask_generic_short() {
        assert_eq!(mask_generic("abc"), "****");
    }

    #[test]
    fn mask_generic_long() {
        assert_eq!(mask_generic("sk_live_abc123def456"), "sk_l****************");
    }
}
