//! Core types for the capability engine.
//!
//! Provides the unified object model where everything is an object with a
//! capability space, and the `PolicyBackend` trait for pluggable policy evaluation.

use hessra_token_core::TokenTimeConfig;
use serde::{Deserialize, Serialize};

/// Object identifier in the unified namespace.
///
/// Object IDs are strings with conventional prefixes for human readability:
/// `service:api-gateway`, `agent:openclaw`, `data:user-ssn`, `tool:web-search`.
/// The engine does not interpret the prefix -- all objects are treated uniformly.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ObjectId(pub String);

impl ObjectId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for ObjectId {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ObjectId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Operation on a target object.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Operation(pub String);

impl Operation {
    pub fn new(op: impl Into<String>) -> Self {
        Self(op.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for Operation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for Operation {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for Operation {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// Taint label for information flow control.
///
/// Taint labels are hierarchical strings representing data sensitivity classifications:
/// `PII:SSN`, `PHI:diagnosis`, `financial:account-number`.
/// Wildcard matching (e.g., `PII:*`) is supported in policy rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaintLabel(pub String);

impl TaintLabel {
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TaintLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for TaintLabel {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for TaintLabel {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// A capability grant: permission for a subject to perform operations on a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The target object this capability grants access to.
    pub target: ObjectId,
    /// The operations allowed on the target.
    pub operations: Vec<Operation>,
}

/// Result of minting a capability token.
///
/// Contains the capability token and optionally an updated context token
/// with taint labels applied if the target was a classified data source.
pub struct MintResult {
    /// The minted capability token (base64-encoded).
    pub token: String,
    /// Updated context token with taint labels, if a context was provided
    /// and the target had data classifications.
    pub context: Option<crate::ContextToken>,
}

/// Options for customizing capability minting beyond the basic case.
///
/// Used with `CapabilityEngine::mint_capability_with_options` to add namespace
/// restrictions or custom time configuration to minted tokens.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    /// Restrict the token to a specific namespace.
    pub namespace: Option<String>,
    /// Override the default time config. If `None`, uses default (5 minutes).
    pub time_config: Option<TokenTimeConfig>,
}

/// A designation label-value pair for narrowing capability scope.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Designation {
    pub label: String,
    pub value: String,
}

/// Configuration for minting identity tokens.
#[derive(Debug, Clone)]
pub struct IdentityConfig {
    /// Token time-to-live in seconds.
    pub ttl: i64,
    /// Whether the identity token can be delegated to sub-identities.
    pub delegatable: bool,
    /// Optional namespace restriction.
    pub namespace: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            ttl: 3600,
            delegatable: false,
            namespace: None,
        }
    }
}

/// Configuration for context token sessions.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Session time-to-live in seconds.
    pub ttl: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self { ttl: 3600 }
    }
}

/// Result of a policy evaluation.
#[derive(Debug, Clone)]
pub enum PolicyDecision {
    /// The capability request is granted.
    Granted,
    /// The capability request is denied by policy (object doesn't hold this capability).
    Denied { reason: String },
    /// The capability request is denied due to taint restrictions.
    DeniedByTaint {
        label: TaintLabel,
        blocked_target: ObjectId,
    },
}

impl PolicyDecision {
    pub fn is_granted(&self) -> bool {
        matches!(self, PolicyDecision::Granted)
    }
}

/// Pluggable policy backend trait.
///
/// Implementations evaluate capability requests against their policy model.
/// The default implementation is the CList backend in `hessra-cap-policy`.
pub trait PolicyBackend: Send + Sync {
    /// Evaluate whether a subject can access a target with the given operation,
    /// considering any taint labels from the subject's context.
    fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        taint_labels: &[TaintLabel],
    ) -> PolicyDecision;

    /// Get the data classification (taint labels) for a target.
    ///
    /// When the engine mints a capability for a classified target, these labels
    /// are automatically added to the subject's context token.
    fn classification(&self, target: &ObjectId) -> Vec<TaintLabel>;

    /// List all capability grants for a subject (for introspection and audit).
    fn list_grants(&self, subject: &ObjectId) -> Vec<CapabilityGrant>;

    /// Check if a subject can delegate capabilities to other objects.
    fn can_delegate(&self, subject: &ObjectId) -> bool;
}
