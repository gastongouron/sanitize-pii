//! # sanitize-pii
//!
//! Detect and mask personally identifiable information (PII) in strings.
//!
//! ```
//! use sanitize_pii::Sanitizer;
//!
//! let sanitizer = Sanitizer::default();
//! let output = sanitizer.sanitize("Contact joe@gmail.com about order");
//! assert_eq!(output, "Contact j***@***.com about order");
//! ```

mod detector;
mod mask;
mod sanitizer;

pub use detector::{Detection, Detector, PiiKind};
pub use sanitizer::{Sanitizer, SanitizerBuilder};
