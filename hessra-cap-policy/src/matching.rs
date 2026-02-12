//! Glob-style pattern matching for taint labels and object IDs.

use glob_match::glob_match;

/// Check if a value matches a pattern.
///
/// Supports glob-style patterns:
/// - `*` matches any sequence of characters
/// - `PII:*` matches `PII:SSN`, `PII:email`, etc.
/// - `tool:*` matches `tool:web-search`, `tool:email`, etc.
/// - Exact strings match exactly.
pub fn matches_pattern(pattern: &str, value: &str) -> bool {
    glob_match(pattern, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        assert!(matches_pattern("PII:SSN", "PII:SSN"));
        assert!(!matches_pattern("PII:SSN", "PII:email"));
    }

    #[test]
    fn test_wildcard_match() {
        assert!(matches_pattern("PII:*", "PII:SSN"));
        assert!(matches_pattern("PII:*", "PII:email"));
        assert!(!matches_pattern("PII:*", "PHI:diagnosis"));
    }

    #[test]
    fn test_tool_wildcard() {
        assert!(matches_pattern("tool:*", "tool:web-search"));
        assert!(matches_pattern("tool:*", "tool:email"));
        assert!(!matches_pattern("tool:*", "service:api-gateway"));
    }

    #[test]
    fn test_full_wildcard() {
        assert!(matches_pattern("*", "anything"));
        assert!(matches_pattern("*", "tool:web-search"));
    }
}
