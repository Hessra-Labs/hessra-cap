//! Context token wrapper for the capability engine.
//!
//! Delegates to `hessra-context-token` for all token operations,
//! wrapping with engine types (ObjectId, ExposureLabel, SessionConfig, EngineError).

use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};

use crate::error::EngineError;
use crate::types::{ExposureLabel, ObjectId, SessionConfig};

/// A context token tracking data exposure for an object.
///
/// Context tokens are append-only: exposure labels can be added but never removed.
/// The token is a base64-encoded Biscuit with an authority block identifying
/// the session and subsequent blocks recording exposure labels.
#[derive(Debug, Clone)]
pub struct ContextToken {
    /// The base64-encoded Biscuit token.
    token: String,
    /// Cached exposure labels extracted from the token (kept in sync).
    exposure_labels: Vec<ExposureLabel>,
}

impl ContextToken {
    /// Create a ContextToken from a raw base64 token string and known exposure labels.
    pub(crate) fn new(token: String, exposure_labels: Vec<ExposureLabel>) -> Self {
        Self {
            token,
            exposure_labels,
        }
    }

    /// Get the base64-encoded token string.
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Get the current exposure labels.
    pub fn exposure_labels(&self) -> &[ExposureLabel] {
        &self.exposure_labels
    }

    /// Check if this context has a specific exposure label.
    pub fn has_exposure(&self, label: &ExposureLabel) -> bool {
        self.exposure_labels.contains(label)
    }

    /// Check if this context has any exposure labels.
    pub fn is_exposed(&self) -> bool {
        !self.exposure_labels.is_empty()
    }
}

/// Builder for creating Hessra context tokens.
///
/// Wraps `hessra_context_token::HessraContext` with engine types.
pub struct HessraContext {
    subject: ObjectId,
    session_config: SessionConfig,
    compound_rejects: Vec<(ExposureLabel, ExposureLabel)>,
}

impl HessraContext {
    /// Creates a new context token builder.
    pub fn new(subject: ObjectId, session_config: SessionConfig) -> Self {
        Self {
            subject,
            session_config,
            compound_rejects: Vec::new(),
        }
    }

    /// Seed two-label compound reject rules into the authority block. Each pair
    /// becomes a `reject if exposure(a), exposure(b)` rule that fires only when
    /// both labels are asserted together at mint time.
    pub fn with_compound_rejects(mut self, rules: Vec<(ExposureLabel, ExposureLabel)>) -> Self {
        self.compound_rejects = rules;
        self
    }

    /// Issues (builds and signs) the context token.
    pub fn issue(self, keypair: &KeyPair) -> Result<ContextToken, EngineError> {
        let time_config = TokenTimeConfig {
            start_time: None,
            duration: self.session_config.ttl,
        };

        let mut builder = hessra_context_token::HessraContext::new(
            self.subject.as_str().to_string(),
            time_config,
        );
        for (first, second) in &self.compound_rejects {
            builder = builder
                .with_compound_reject(first.as_str().to_string(), second.as_str().to_string());
        }

        let token = builder
            .issue(keypair)
            .map_err(|e| EngineError::Context(format!("failed to mint context token: {e}")))?;

        Ok(ContextToken::new(token, vec![]))
    }
}

/// Verify a context token while asserting `labels` as candidate
/// `exposure({label})` facts. Returns `Ok(())` if no `reject if exposure(...)`
/// rule in the token fires for the asserted facts, or
/// [`EngineError::ExposureBlocked`] if one does (or the token is otherwise
/// invalid). This is the single exposure-enforcement mechanism: the decision is
/// made by the token's reject rules, not by the policy backend.
pub fn verify_excluding(
    token: &str,
    public_key: PublicKey,
    labels: &[ExposureLabel],
    target: &ObjectId,
) -> Result<(), EngineError> {
    let mut verifier = hessra_context_token::ContextVerifier::new(token.to_string(), public_key);
    for label in labels {
        verifier = verifier.excludes(label.as_str().to_string());
    }
    verifier.verify().map_err(|_| EngineError::ExposureBlocked {
        labels: labels.to_vec(),
        target: target.clone(),
    })
}

/// Add exposure labels to a context token.
pub fn add_exposure_block(
    context: &ContextToken,
    labels: &[ExposureLabel],
    source: &ObjectId,
    keypair: &KeyPair,
) -> Result<ContextToken, EngineError> {
    if labels.is_empty() {
        return Ok(context.clone());
    }

    let label_strings: Vec<String> = labels.iter().map(|l| l.as_str().to_string()).collect();

    let new_token = hessra_context_token::add_exposure(
        context.token(),
        keypair,
        &label_strings,
        source.as_str().to_string(),
    )
    .map_err(|e| EngineError::Context(format!("failed to add exposure: {e}")))?;

    // Merge labels
    let mut all_labels = context.exposure_labels().to_vec();
    for label in labels {
        if !all_labels.contains(label) {
            all_labels.push(label.clone());
        }
    }

    Ok(ContextToken::new(new_token, all_labels))
}

/// Extract all exposure labels from a context token by re-parsing the Biscuit.
pub fn extract_exposure_labels(
    token: &str,
    public_key: PublicKey,
) -> Result<Vec<ExposureLabel>, EngineError> {
    let labels = hessra_context_token::extract_exposure_labels(token, public_key)
        .map_err(|e| EngineError::Context(format!("failed to extract exposure labels: {e}")))?;

    Ok(labels.into_iter().map(ExposureLabel::new).collect())
}

/// Fork a context token for a sub-agent, inheriting the parent's exposure.
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

    // Extract exposure labels from the new child token
    let exposure_labels =
        hessra_context_token::extract_exposure_labels(&child_token, keypair.public())
            .map_err(|e| EngineError::Context(format!("failed to extract child exposure: {e}")))?
            .into_iter()
            .map(ExposureLabel::new)
            .collect();

    Ok(ContextToken::new(child_token, exposure_labels))
}
