//! Context token implementation for information flow control (taint tracking).
//!
//! Context tokens track what data an object (typically an AI agent) has been
//! exposed to. Each data access adds taint labels as append-only Biscuit blocks,
//! which the engine then uses to restrict available capabilities.
//!
//! Taint labels accumulate and cannot be removed within a session. This prevents
//! data contamination from being laundered through delegation or sub-agents.

mod mint;
mod taint;
mod verify;

pub use mint::HessraContext;
pub use taint::{add_taint_block, extract_taint_labels, fork_context};
pub use verify::ContextVerifier;

use crate::types::TaintLabel;

/// A context token tracking data exposure for an object.
///
/// Context tokens are append-only: taint labels can be added but never removed.
/// The token is a base64-encoded Biscuit with an authority block identifying
/// the session and subsequent blocks recording taint labels.
#[derive(Debug, Clone)]
pub struct ContextToken {
    /// The base64-encoded Biscuit token.
    token: String,
    /// Cached taint labels extracted from the token (kept in sync).
    taint_labels: Vec<TaintLabel>,
}

impl ContextToken {
    /// Create a ContextToken from a raw base64 token string and known taint labels.
    pub(crate) fn new(token: String, taint_labels: Vec<TaintLabel>) -> Self {
        Self {
            token,
            taint_labels,
        }
    }

    /// Get the base64-encoded token string.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Get the current taint labels.
    pub fn taint_labels(&self) -> &[TaintLabel] {
        &self.taint_labels
    }

    /// Check if this context has a specific taint label.
    pub fn has_taint(&self, label: &TaintLabel) -> bool {
        self.taint_labels.contains(label)
    }

    /// Check if this context has any taint labels.
    pub fn is_tainted(&self) -> bool {
        !self.taint_labels.is_empty()
    }
}
