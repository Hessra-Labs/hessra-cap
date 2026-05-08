//! Error types for the capability engine.

use crate::resolver::ResolverError;
use crate::types::{ExposureLabel, ObjectId, Operation};
use thiserror::Error;

/// Errors from the capability engine.
#[derive(Error, Debug)]
pub enum EngineError {
    /// Capability request denied by policy.
    #[error("capability denied: {subject} cannot perform '{operation}' on '{target}': {reason}")]
    CapabilityDenied {
        subject: ObjectId,
        target: ObjectId,
        operation: Operation,
        reason: String,
    },

    /// Capability request denied due to exposure restriction.
    #[error("capability denied by exposure: label '{label}' blocks access to '{target}'")]
    ExposureRestriction {
        label: ExposureLabel,
        target: ObjectId,
    },

    /// Identity token operation failed.
    #[error("identity error: {0}")]
    Identity(String),

    /// Context token operation failed.
    #[error("context error: {0}")]
    Context(String),

    /// Token error from underlying token crate.
    #[error("token error: {0}")]
    Token(#[from] hessra_token_core::TokenError),

    /// Token creation or verification failed.
    #[error("token operation failed: {0}")]
    TokenOperation(String),

    /// Policy backend error.
    #[error("policy error: {0}")]
    Policy(String),

    /// A required designation declared in the schema was not supplied at mint
    /// time (neither by the policy declaration nor by the caller).
    #[error("missing required designation '{label}' for target '{target}' operation '{operation}'")]
    MissingRequiredDesignation {
        target: ObjectId,
        operation: Operation,
        label: String,
    },

    /// A static designation declared in policy references a label that does
    /// not appear in the target's schema for the matched operation.
    /// Surfaced at engine construction.
    #[error(
        "policy declares static designation '{label}' for target '{target}' operation '{operation}', but the schema does not declare that label"
    )]
    UnknownLabelInPolicy {
        target: ObjectId,
        operation: Operation,
        label: String,
    },

    /// Cross-validation between policy and schema failed at engine construction.
    /// Either a policy-declared static designation references an unknown label
    /// (see [`EngineError::UnknownLabelInPolicy`]) or another structural
    /// mismatch was detected.
    #[error("schema/policy mismatch: {0}")]
    SchemaPolicyMismatch(String),

    /// A designation resolver failed during a `mint_with_context` call.
    #[error("resolver error: {0}")]
    Resolver(#[from] ResolverError),

    /// The mint failed the delegated identity chain check: an ancestor of
    /// `subject` does not hold a grant for `(target, operation)`. This
    /// enforces "sub-identity capabilities ⊆ parent identity capabilities"
    /// transitively.
    #[error(
        "chain check failed: ancestor '{ancestor}' of '{subject}' does not have grant for '{operation}' on '{target}'"
    )]
    ChainCheckFailed {
        subject: ObjectId,
        ancestor: ObjectId,
        target: ObjectId,
        operation: Operation,
    },
}
