use once_cell::sync::Lazy;
use regex::Regex;

/// The kind of PII detected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PiiKind {
    Email,
    CreditCard,
    Phone,
    IpV4,
    IpV6,
    ApiKey(String),
    Custom(String),
}

impl std::fmt::Display for PiiKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PiiKind::Email => write!(f, "email"),
            PiiKind::CreditCard => write!(f, "credit_card"),
            PiiKind::Phone => write!(f, "phone"),
            PiiKind::IpV4 => write!(f, "ipv4"),
            PiiKind::IpV6 => write!(f, "ipv6"),
            PiiKind::ApiKey(name) => write!(f, "api_key:{name}"),
            PiiKind::Custom(name) => write!(f, "custom:{name}"),
        }
    }
}

/// A single PII match found in the input string.
#[derive(Debug, Clone)]
pub struct Detection {
    pub kind: PiiKind,
    pub start: usize,
    pub end: usize,
    pub matched: String,
}

/// A detector for a specific kind of PII.
pub struct Detector {
    pub kind: PiiKind,
    pub regex: Regex,
    pub validate: Option<fn(&str) -> bool>,
}

impl Detector {
    pub fn new(kind: PiiKind, regex: Regex) -> Self {
        Self {
            kind,
            regex,
            validate: None,
        }
    }

    pub fn with_validation(mut self, validate: fn(&str) -> bool) -> Self {
        self.validate = Some(validate);
        self
    }

    pub fn detect(&self, input: &str) -> Vec<Detection> {
        self.regex
            .find_iter(input)
            .filter(|m| self.validate.is_none_or(|v| v(m.as_str())))
            .map(|m| Detection {
                kind: self.kind.clone(),
                start: m.start(),
                end: m.end(),
                matched: m.as_str().to_string(),
            })
            .collect()
    }
}

// --- Built-in detectors ---

static EMAIL_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}").unwrap());

static CREDIT_CARD_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b").unwrap());

static PHONE_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(\+?\d{1,3}[\s\-]?)?\(?\d{2,4}\)?[\s\-]?\d{3,4}[\s\-]?\d{3,4}\b").unwrap()
});

static IPV4_RE: Lazy<Regex> = Lazy::new(|| {
    Regex::new(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
        .unwrap()
});

static IPV6_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\b(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}\b").unwrap());

static API_KEY_STRIPE_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b[sr]k_(live|test)_[a-zA-Z0-9]{20,}\b").unwrap());

static API_KEY_GITHUB_RE: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}\b").unwrap());

static API_KEY_AWS_RE: Lazy<Regex> = Lazy::new(|| Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap());

/// Luhn algorithm for credit card validation.
pub fn luhn_check(input: &str) -> bool {
    let digits: Vec<u32> = input
        .chars()
        .filter(|c| c.is_ascii_digit())
        .map(|c| c.to_digit(10).unwrap())
        .collect();

    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }

    let checksum: u32 = digits
        .iter()
        .rev()
        .enumerate()
        .map(|(i, &d)| {
            if i % 2 == 1 {
                let doubled = d * 2;
                if doubled > 9 {
                    doubled - 9
                } else {
                    doubled
                }
            } else {
                d
            }
        })
        .sum();

    checksum.is_multiple_of(10)
}

pub fn builtin_email() -> Detector {
    Detector::new(PiiKind::Email, EMAIL_RE.clone())
}

pub fn builtin_credit_card() -> Detector {
    Detector::new(PiiKind::CreditCard, CREDIT_CARD_RE.clone()).with_validation(luhn_check)
}

pub fn builtin_phone() -> Detector {
    Detector::new(PiiKind::Phone, PHONE_RE.clone())
}

pub fn builtin_ipv4() -> Detector {
    Detector::new(PiiKind::IpV4, IPV4_RE.clone())
}

pub fn builtin_ipv6() -> Detector {
    Detector::new(PiiKind::IpV6, IPV6_RE.clone())
}

pub fn builtin_api_keys() -> Vec<Detector> {
    vec![
        Detector::new(PiiKind::ApiKey("stripe".into()), API_KEY_STRIPE_RE.clone()),
        Detector::new(PiiKind::ApiKey("github".into()), API_KEY_GITHUB_RE.clone()),
        Detector::new(PiiKind::ApiKey("aws".into()), API_KEY_AWS_RE.clone()),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_email() {
        let d = builtin_email();
        let results = d.detect("send to alice@example.com please");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "alice@example.com");
    }

    #[test]
    fn detect_credit_card_valid() {
        let d = builtin_credit_card();
        // Valid Visa test number
        let results = d.detect("card: 4111 1111 1111 1111");
        assert_eq!(results.len(), 1);
    }

    #[test]
    fn reject_credit_card_invalid_luhn() {
        let d = builtin_credit_card();
        let results = d.detect("card: 1234 5678 9012 3456");
        assert_eq!(results.len(), 0);
    }

    #[test]
    fn detect_ipv4() {
        let d = builtin_ipv4();
        let results = d.detect("server at 192.168.1.1 responded");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].matched, "192.168.1.1");
    }

    #[test]
    fn luhn_valid() {
        assert!(luhn_check("4111111111111111"));
        assert!(luhn_check("5500 0000 0000 0004"));
    }

    #[test]
    fn luhn_invalid() {
        assert!(!luhn_check("1234567890123456"));
    }
}
