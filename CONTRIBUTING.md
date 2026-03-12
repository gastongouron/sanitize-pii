# Contributing to sanitize-pii

Thanks for your interest in contributing!

## Getting started

1. Fork the repo and clone your fork
2. Create a feature branch: `git checkout -b feat/my-feature`
3. Make your changes and add tests
4. Run the checks locally:
   ```bash
   cargo test
   cargo clippy -- -D warnings
   cargo fmt -- --check
   ```
5. Open a PR against `main`

## Adding a new PII detector

1. Add your regex pattern and detector function in `src/detector.rs`
2. Add the corresponding masking logic in `src/mask.rs`
3. Wire it into `SanitizerBuilder` in `src/sanitizer.rs`
4. Add tests for detection, masking, and end-to-end sanitization

## Guidelines

- Every new detector needs tests (detection + masking + integration)
- Avoid false positives — add validation where possible (like Luhn for credit cards)
- Keep regex patterns readable, add a comment if they're complex
- Run `cargo fmt` before committing
