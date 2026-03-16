//! Error types for the capability engine.

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
}
