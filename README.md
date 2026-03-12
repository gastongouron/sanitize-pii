# sanitize-pii

[![CI](https://github.com/gastongouron/sanitize-pii/actions/workflows/ci.yml/badge.svg)](https://github.com/gastongouron/sanitize-pii/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/gastongouron/sanitize-pii/branch/main/graph/badge.svg)](https://codecov.io/gh/gastongouron/sanitize-pii)
[![Crates.io](https://img.shields.io/crates/v/sanitize-pii.svg)](https://crates.io/crates/sanitize-pii)
[![docs.rs](https://docs.rs/sanitize-pii/badge.svg)](https://docs.rs/sanitize-pii)

Detect and mask personally identifiable information (PII) in strings. Useful for sanitizing logs, error reports, and data exports before they leave your system.

## Built-in detectors

| Type | Example input | Masked output |
|------|--------------|---------------|
| Email | `joe@gmail.com` | `j***@***.com` |
| Credit card | `4111 1111 1111 1111` | `4111-****-****-1111` |
| Phone number | `+33 6 12 34 56 78` | `+** * ** ** ** 78` |
| IPv4 | `192.168.1.42` | `192.***.***.42` |
| IPv6 | `2001:0db8:...` | `***:***:***:***` |
| API keys | `sk_live_abc123...` | `sk_l****...` |

Credit card detection includes Luhn algorithm validation to avoid false positives.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
sanitize-pii = "0.1"
```

### Sanitize a string (all detectors)

```rust
use sanitize_pii::Sanitizer;

let sanitizer = Sanitizer::default();
let clean = sanitizer.sanitize("Contact joe@gmail.com about order");
assert_eq!(clean, "Contact j***@***.com about order");
```

### Pick specific detectors

```rust
use sanitize_pii::Sanitizer;

let sanitizer = Sanitizer::builder()
    .email()
    .credit_card()
    .build();

let clean = sanitizer.sanitize("bob@test.com at 192.168.1.1");
// IP is untouched because we only enabled email + credit card
assert!(clean.contains("192.168.1.1"));
```

### Detect without masking

```rust
use sanitize_pii::Sanitizer;

let sanitizer = Sanitizer::default();
let detections = sanitizer.detect("email: alice@example.com");

assert_eq!(detections.len(), 1);
assert_eq!(detections[0].matched, "alice@example.com");
println!("Found {} at position {}..{}", detections[0].kind, detections[0].start, detections[0].end);
```

### Add custom patterns

```rust
use sanitize_pii::Sanitizer;

let sanitizer = Sanitizer::builder()
    .email()
    .custom("ssn", r"\b\d{3}-\d{2}-\d{4}\b")
    .build();

let clean = sanitizer.sanitize("SSN: 123-45-6789");
assert!(clean.contains("****"));
```

## Use cases

- **Logging:** wrap your logger to strip PII before writing
- **Error reporting:** sanitize before sending to Sentry, Datadog, etc.
- **Data exports:** clean dumps before sharing or archiving
- **GDPR compliance:** ensure PII doesn't leak into unprotected storage

## License

MIT
