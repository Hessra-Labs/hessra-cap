//! Context token wrapper for the capability engine.
//!
//! Delegates to `hessra-context-token` for all token operations,
//! wrapping with engine types (ObjectId, TaintLabel, SessionConfig, EngineError).

use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};

use crate::error::EngineError;
use crate::types::{ObjectId, SessionConfig, TaintLabel};

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

/// Builder for creating Hessra context tokens.
///
/// Wraps `hessra_context_token::HessraContext` with engine types.
pub struct HessraContext {
    subject: ObjectId,
    session_config: SessionConfig,
}

impl HessraContext {
    /// Creates a new context token builder.
    pub fn new(subject: ObjectId, session_config: SessionConfig) -> Self {
        Self {
            subject,
            session_config,
        }
    }

    /// Issues (builds and signs) the context token.
    pub fn issue(self, keypair: &KeyPair) -> Result<ContextToken, EngineError> {
        let time_config = TokenTimeConfig {
            start_time: None,
            duration: self.session_config.ttl,
        };

        let token = hessra_context_token::HessraContext::new(
            self.subject.as_str().to_string(),
            time_config,
        )
        .issue(keypair)
        .map_err(|e| EngineError::Context(format!("failed to mint context token: {e}")))?;

        Ok(ContextToken::new(token, vec![]))
    }
}

/// Add taint labels to a context token.
pub fn add_taint_block(
    context: &ContextToken,
    labels: &[TaintLabel],
    source: &ObjectId,
    keypair: &KeyPair,
) -> Result<ContextToken, EngineError> {
    if labels.is_empty() {
        return Ok(context.clone());
    }

    let label_strings: Vec<String> = labels.iter().map(|l| l.as_str().to_string()).collect();

    let new_token = hessra_context_token::add_taint(
        context.token(),
        keypair.public(),
        &label_strings,
        source.as_str().to_string(),
    )
    .map_err(|e| EngineError::Context(format!("failed to add taint: {e}")))?;

    // Merge labels
    let mut all_labels = context.taint_labels().to_vec();
    for label in labels {
        if !all_labels.contains(label) {
            all_labels.push(label.clone());
        }
    }

    Ok(ContextToken::new(new_token, all_labels))
}

/// Extract all taint labels from a context token by re-parsing the Biscuit.
pub fn extract_taint_labels(
    token: &str,
    public_key: PublicKey,
) -> Result<Vec<TaintLabel>, EngineError> {
    let labels = hessra_context_token::extract_taint_labels(token, public_key)
        .map_err(|e| EngineError::Context(format!("failed to extract taint labels: {e}")))?;

    Ok(labels.into_iter().map(TaintLabel::new).collect())
}

/// Fork a context token for a sub-agent, inheriting the parent's taint.
pub fn fork_context(
    parent: &ContextToken,
    child_subject: &ObjectId,
    session_config: SessionConfig,
    keypair: &KeyPair,
) -> Result<ContextToken, EngineError> {
    let time_config = TokenTimeConfig {
        start_time: None,
        duration: session_config.ttl,
    };

    let child_token = hessra_context_token::fork_context(
        parent.token(),
        keypair.public(),
        child_subject.as_str().to_string(),
        time_config,
        keypair,
    )
    .map_err(|e| EngineError::Context(format!("failed to fork context: {e}")))?;

    // Extract taint labels from the new child token
    let taint_labels = hessra_context_token::extract_taint_labels(&child_token, keypair.public())
        .map_err(|e| EngineError::Context(format!("failed to extract child taint: {e}")))?
        .into_iter()
        .map(TaintLabel::new)
        .collect();

    Ok(ContextToken::new(child_token, taint_labels))
}
