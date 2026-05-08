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

/// Exposure label for information flow control.
///
/// Exposure labels are hierarchical strings representing data sensitivity classifications:
/// `PII:SSN`, `PHI:diagnosis`, `financial:account-number`.
/// Wildcard matching (e.g., `PII:*`) is supported in policy rules.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExposureLabel(pub String);

impl ExposureLabel {
    pub fn new(label: impl Into<String>) -> Self {
        Self(label.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for ExposureLabel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<&str> for ExposureLabel {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for ExposureLabel {
    fn from(s: String) -> Self {
        Self(s)
    }
}

/// How a capability declaration binds the principal that can verify the
/// issued capability.
///
/// At verify time, the verifier proves "I am `<anchor>`" by supplying
/// `Designation { label: "anchor", value: <its-own-principal-name> }`. The
/// capability is honored only by the named principal. A receiving principal
/// who is not the anchor can still attenuate and delegate the capability
/// downward; the capability simply must eventually be presented back to the
/// anchor for verification.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AnchorBinding {
    /// Anchor to the subject of this declaration. The engine resolves to a
    /// concrete principal at mint time.
    Subject,
    /// Anchor to a specific named principal (trustee or multi-organization
    /// pattern).
    Principal(ObjectId),
}

/// A capability grant: permission for a subject to perform operations on a target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilityGrant {
    /// The target object this capability grants access to.
    pub target: ObjectId,
    /// The operations allowed on the target.
    pub operations: Vec<Operation>,
    /// Anchor binding for issued capabilities under this declaration. `None`
    /// means the capability is not anchored and can be verified by any
    /// principal.
    pub anchor: Option<AnchorBinding>,
    /// Static designations attached at every mint of this declaration.
    /// Author-time bindings declared in policy. Each label is validated
    /// against the target's schema at engine construction.
    #[serde(default)]
    pub designations: Vec<Designation>,
}

/// Result of minting a capability token.
///
/// Contains the capability token and optionally an updated context token
/// with exposure labels applied if the target was a classified data source.
pub struct MintResult {
    /// The minted capability token (base64-encoded).
    pub token: String,
    /// Updated context token with exposure labels, if a context was provided
    /// and the target had data classifications.
    pub context: Option<crate::ContextToken>,
}

/// Options for customizing capability minting beyond the basic case.
///
/// Used with `CapabilityEngine::mint_capability_with_options` and
/// `CapabilityEngine::issue_capability` to override the policy's default
/// anchor configuration or set a custom token lifetime.
#[derive(Debug, Clone, Default)]
pub struct MintOptions {
    /// Override the policy's anchor configuration with an explicit principal.
    /// When set, the engine attaches `designation("anchor", value)` to the
    /// minted capability, regardless of what the policy declares. Used for
    /// the `issue_capability` path (which skips policy) and for explicit
    /// caller intent.
    pub anchor: Option<ObjectId>,
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
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            ttl: 3600,
            delegatable: false,
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
    /// The capability request is granted. `anchor` carries the resolved anchor
    /// principal, if the matched declaration is anchor-bound. The CList policy
    /// resolves `AnchorBinding::Subject` to the requesting subject before
    /// returning, so the engine sees a concrete principal id (or `None`).
    /// `designations` carries author-time static designations declared in the
    /// matched policy entry; the engine attaches these at mint time alongside
    /// any caller-supplied designations and validates the union against the
    /// target's schema.
    Granted {
        anchor: Option<ObjectId>,
        designations: Vec<Designation>,
    },
    /// The capability request is denied by policy (object doesn't hold this capability).
    Denied { reason: String },
    /// The capability request is denied due to exposure restrictions.
    DeniedByExposure {
        label: ExposureLabel,
        blocked_target: ObjectId,
    },
}

impl PolicyDecision {
    pub fn is_granted(&self) -> bool {
        matches!(self, PolicyDecision::Granted { .. })
    }
}

/// Pluggable policy backend trait.
///
/// Implementations evaluate capability requests against their policy model.
/// The default implementation is the CList backend in `hessra-cap-policy`.
pub trait PolicyBackend: Send + Sync {
    /// Evaluate whether a subject can access a target with the given operation,
    /// considering any exposure labels from the subject's context.
    fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        exposure_labels: &[ExposureLabel],
    ) -> PolicyDecision;

    /// Get the data classification (exposure labels) for a target.
    ///
    /// When the engine mints a capability for a classified target, these labels
    /// are automatically added to the subject's context token.
    fn classification(&self, target: &ObjectId) -> Vec<ExposureLabel>;

    /// List all capability grants for a subject (for introspection and audit).
    fn list_grants(&self, subject: &ObjectId) -> Vec<CapabilityGrant>;

    /// Check if a subject can delegate capabilities to other objects.
    fn can_delegate(&self, subject: &ObjectId) -> bool;

    /// Enumerate every (subject, grant) pair the policy declares. Used by the
    /// engine to cross-validate static designations against schemas at
    /// construction time. The default implementation returns an empty vector,
    /// which disables schema cross-validation; backends that store grants
    /// statically (e.g., CList) should override this.
    fn all_grants(&self) -> Vec<(ObjectId, CapabilityGrant)> {
        Vec::new()
    }

    /// The immediate parent principal of `subject` in the principal graph,
    /// if `subject` is a sub-identity. Returns `None` for root principals or
    /// principals not declared in this backend.
    ///
    /// Used by the engine's chain check at mint time. The default returns
    /// `None`, modeling a flat principal graph; backends that represent
    /// parent-child relationships (e.g., CList via `ObjectConfig.parent`)
    /// should override this.
    fn parent(&self, _subject: &ObjectId) -> Option<ObjectId> {
        None
    }

    /// Whether `subject` holds a grant for `(target, operation)`, ignoring
    /// any current exposure context. Used by the engine's chain check to
    /// verify ancestor authority without conflating exposure (which is the
    /// requesting subject's own running state, not an inherited property).
    ///
    /// The default delegates to `evaluate(..., &[])` and matches
    /// `PolicyDecision::Granted { .. }`. Backends with a more efficient
    /// capability-space lookup may override.
    fn has_grant(&self, subject: &ObjectId, target: &ObjectId, operation: &Operation) -> bool {
        matches!(
            self.evaluate(subject, target, operation, &[]),
            PolicyDecision::Granted { .. },
        )
    }
}
