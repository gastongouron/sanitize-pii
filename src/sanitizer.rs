use regex::Regex;

use crate::detector::{
    self, Detection, Detector, PiiKind,
};
use crate::mask;

/// The main entry point for sanitizing strings.
///
/// ```
/// use sanitize_pii::Sanitizer;
///
/// let s = Sanitizer::default();
/// let clean = s.sanitize("email: test@example.com");
/// assert!(clean.contains("***"));
/// ```
pub struct Sanitizer {
    detectors: Vec<Detector>,
}

impl Default for Sanitizer {
    fn default() -> Self {
        SanitizerBuilder::new()
            .email()
            .credit_card()
            .phone()
            .ipv4()
            .ipv6()
            .api_keys()
            .build()
    }
}

impl Sanitizer {
    pub fn builder() -> SanitizerBuilder {
        SanitizerBuilder::new()
    }

    /// Detect all PII in the input string.
    pub fn detect(&self, input: &str) -> Vec<Detection> {
        let mut all: Vec<Detection> = self
            .detectors
            .iter()
            .flat_map(|d| d.detect(input))
            .collect();

        // Sort by position, longest match first for overlaps
        all.sort_by(|a, b| a.start.cmp(&b.start).then(b.end.cmp(&a.end)));
        all
    }

    /// Sanitize the input string, replacing all detected PII with masked versions.
    pub fn sanitize(&self, input: &str) -> String {
        let detections = self.detect(input);
        if detections.is_empty() {
            return input.to_string();
        }

        let mut result = String::with_capacity(input.len());
        let mut cursor = 0;

        for det in &detections {
            // Skip overlapping detections
            if det.start < cursor {
                continue;
            }
            result.push_str(&input[cursor..det.start]);
            result.push_str(&mask::mask(&det.matched, &det.kind));
            cursor = det.end;
        }

        result.push_str(&input[cursor..]);
        result
    }
}

/// Builder for configuring which PII detectors to use.
pub struct SanitizerBuilder {
    detectors: Vec<Detector>,
}

impl SanitizerBuilder {
    pub fn new() -> Self {
        Self {
            detectors: Vec::new(),
        }
    }

    pub fn email(mut self) -> Self {
        self.detectors.push(detector::builtin_email());
        self
    }

    pub fn credit_card(mut self) -> Self {
        self.detectors.push(detector::builtin_credit_card());
        self
    }

    pub fn phone(mut self) -> Self {
        self.detectors.push(detector::builtin_phone());
        self
    }

    pub fn ipv4(mut self) -> Self {
        self.detectors.push(detector::builtin_ipv4());
        self
    }

    pub fn ipv6(mut self) -> Self {
        self.detectors.push(detector::builtin_ipv6());
        self
    }

    pub fn api_keys(mut self) -> Self {
        self.detectors.extend(detector::builtin_api_keys());
        self
    }

    /// Add a custom detector with a name and regex pattern.
    pub fn custom(mut self, name: &str, pattern: &str) -> Self {
        if let Ok(regex) = Regex::new(pattern) {
            self.detectors
                .push(Detector::new(PiiKind::Custom(name.to_string()), regex));
        }
        self
    }

    pub fn build(self) -> Sanitizer {
        Sanitizer {
            detectors: self.detectors,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_email() {
        let s = Sanitizer::default();
        let result = s.sanitize("Contact joe@gmail.com about order");
        assert_eq!(result, "Contact j***@***.com about order");
    }

    #[test]
    fn sanitize_credit_card() {
        let s = Sanitizer::default();
        let result = s.sanitize("card: 4111 1111 1111 1111");
        assert_eq!(result, "card: 4111-****-****-1111");
    }

    #[test]
    fn sanitize_ipv4() {
        let s = Sanitizer::default();
        let result = s.sanitize("server 192.168.1.42 is down");
        assert_eq!(result, "server 192.***.***.42 is down");
    }

    #[test]
    fn sanitize_multiple_pii() {
        let s = Sanitizer::default();
        let result = s.sanitize("user alice@test.org from 10.0.0.1");
        assert!(result.contains("a***@***.org"));
        assert!(result.contains("10.***.***.1"));
    }

    #[test]
    fn sanitize_no_pii() {
        let s = Sanitizer::default();
        let input = "nothing sensitive here";
        assert_eq!(s.sanitize(input), input);
    }

    #[test]
    fn sanitize_custom_pattern() {
        let s = Sanitizer::builder()
            .custom("ssn", r"\b\d{3}-\d{2}-\d{4}\b")
            .build();
        let result = s.sanitize("SSN: 123-45-6789");
        assert!(result.contains("123-"));
        assert!(result.contains("****"));
    }

    #[test]
    fn detect_returns_positions() {
        let s = Sanitizer::builder().email().build();
        let detections = s.detect("hi bob@test.com bye");
        assert_eq!(detections.len(), 1);
        assert_eq!(detections[0].start, 3);
        assert_eq!(detections[0].end, 15);
        assert_eq!(detections[0].kind, PiiKind::Email);
    }

    #[test]
    fn builder_pick_and_choose() {
        let s = Sanitizer::builder().email().build();
        // Should detect email but not IP
        let result = s.sanitize("bob@test.com at 192.168.1.1");
        assert!(result.contains("***@***"));
        assert!(result.contains("192.168.1.1"));
    }
}
