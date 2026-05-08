//! TOML configuration parsing for the CList policy backend.

use serde::Deserialize;
use std::collections::HashMap;
use thiserror::Error;

/// Errors from policy configuration parsing.
#[derive(Error, Debug)]
pub enum PolicyConfigError {
    #[error("failed to read policy file: {0}")]
    Io(#[from] std::io::Error),
    #[error("failed to parse policy TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error(
        "capability declaration on object '{subject}' for target '{target}' specifies both `anchor_to_subject` and `anchor`; these are mutually exclusive"
    )]
    AnchorConflict { subject: String, target: String },
    #[error(
        "capability declaration on object '{subject}' for target '{target}' anchors to '{anchor}', which is not a known principal in this policy"
    )]
    UnknownAnchorPrincipal {
        subject: String,
        target: String,
        anchor: String,
    },
    #[error(
        "object '{subject}' declares parent '{parent}', which is not a known principal in this policy"
    )]
    UnknownParent { subject: String, parent: String },
    #[error(
        "parent chain for object '{}' forms a cycle: {}",
        chain.first().map(String::as_str).unwrap_or("?"),
        chain.join(" -> "),
    )]
    ParentCycle { chain: Vec<String> },
}

/// Top-level policy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Objects and their capability spaces.
    #[serde(default)]
    pub objects: Vec<ObjectConfig>,

    /// Data classifications: maps target object IDs to exposure labels.
    #[serde(default)]
    pub classifications: HashMap<String, Vec<String>>,

    /// Exposure restriction rules.
    #[serde(default)]
    pub exposure_rules: Vec<ExposureRuleConfig>,
}

/// Configuration for a single object and its capability space.
#[derive(Debug, Clone, Deserialize)]
pub struct ObjectConfig {
    /// The object ID (e.g., "service:api-gateway", "agent:openclaw").
    pub id: String,

    /// Whether this object can delegate capabilities.
    #[serde(default)]
    pub can_delegate: bool,

    /// Optional identity token configuration.
    #[serde(default)]
    pub identity: Option<IdentityConfigEntry>,

    /// The object's capability grants.
    #[serde(default)]
    pub capabilities: Vec<CapabilityConfig>,

    /// Optional parent principal id. When set, this object is a sub-identity
    /// of `parent`, and the engine's chain check requires `parent` to hold
    /// every capability minted for this object. Independent of
    /// [`Self::can_delegate`].
    #[serde(default)]
    pub parent: Option<String>,
}

/// Identity token configuration for an object.
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfigEntry {
    /// Token TTL in seconds.
    #[serde(default = "default_ttl")]
    pub ttl: i64,
    /// Whether the identity is delegatable.
    #[serde(default)]
    pub delegatable: bool,
}

fn default_ttl() -> i64 {
    3600
}

/// A single capability declaration.
///
/// Anchor binding is configured via two mutually exclusive fields:
/// - `anchor_to_subject = true`: shorthand for "anchor = the subject of this
///   declaration." This is the common case for delegation patterns where the
///   subject is also the verifying authority.
/// - `anchor = "<principal>"`: explicit anchor to some other principal. Trustee
///   or multi-organization patterns where the issuer mints to one principal but
///   the capability is intended to be verified by another.
///
/// Static designations (`designations = [{ label, value }]`) are author-time
/// bindings the engine attaches at every mint of this declaration. They are
/// validated against the target's schema at engine construction.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityConfig {
    /// The target object ID (e.g., "service:user-service", "tool:web-search").
    pub target: String,
    /// Allowed operations on the target (e.g., ["read", "write"]).
    pub operations: Vec<String>,
    /// Anchor the issued capability to the subject of this declaration.
    /// Mutually exclusive with `anchor`.
    #[serde(default)]
    pub anchor_to_subject: bool,
    /// Anchor the issued capability to a specific principal as the only
    /// authority that can verify it. Mutually exclusive with
    /// `anchor_to_subject`. The principal name must reference an object
    /// declared elsewhere in this policy.
    #[serde(default)]
    pub anchor: Option<String>,
    /// Static designations attached at every mint of this declaration.
    /// Each label must appear in the target's schema for the matched
    /// operation; cross-validation runs at engine construction.
    #[serde(default)]
    pub designations: Vec<DesignationConfig>,
}

/// A static designation `(label, value)` declared by the policy author and
/// attached at every mint of the enclosing capability declaration.
#[derive(Debug, Clone, Deserialize)]
pub struct DesignationConfig {
    pub label: String,
    pub value: String,
}

/// An exposure restriction rule.
#[derive(Debug, Clone, Deserialize)]
pub struct ExposureRuleConfig {
    /// Exposure labels that trigger this rule. Supports glob patterns (e.g., "PII:*").
    pub labels: Vec<String>,

    /// Match mode: "any" (default) or "all".
    /// - "any": rule triggers if any label matches
    /// - "all": rule triggers only if all labels match
    #[serde(default = "default_match_mode")]
    pub r#match: String,

    /// Target object IDs that are blocked when this rule triggers.
    /// Supports glob patterns (e.g., "tool:*").
    pub blocks: Vec<String>,
}

fn default_match_mode() -> String {
    "any".to_string()
}

impl PolicyConfig {
    /// Load policy from a TOML file path.
    pub fn from_file(path: &std::path::Path) -> Result<Self, PolicyConfigError> {
        let content = std::fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Parse policy from a TOML string.
    pub fn parse(content: &str) -> Result<Self, PolicyConfigError> {
        let config: PolicyConfig = toml::from_str(content)?;
        config.validate()?;
        Ok(config)
    }

    /// Cross-cutting validation: anchor mutual exclusion and known-principal
    /// reference checks. Runs after deserialization on every parse.
    fn validate(&self) -> Result<(), PolicyConfigError> {
        let known_principals: std::collections::HashSet<&str> =
            self.objects.iter().map(|o| o.id.as_str()).collect();

        for obj in &self.objects {
            for cap in &obj.capabilities {
                if cap.anchor_to_subject && cap.anchor.is_some() {
                    return Err(PolicyConfigError::AnchorConflict {
                        subject: obj.id.clone(),
                        target: cap.target.clone(),
                    });
                }
                let Some(anchor) = &cap.anchor else {
                    continue;
                };
                if !known_principals.contains(anchor.as_str()) {
                    return Err(PolicyConfigError::UnknownAnchorPrincipal {
                        subject: obj.id.clone(),
                        target: cap.target.clone(),
                        anchor: anchor.clone(),
                    });
                }
            }
        }

        // Parent declarations: every named parent must exist, and chains must
        // be acyclic. Build a parent lookup once for both checks.
        let parent_of: std::collections::HashMap<&str, &str> = self
            .objects
            .iter()
            .filter_map(|o| o.parent.as_deref().map(|p| (o.id.as_str(), p)))
            .collect();

        for obj in &self.objects {
            let Some(parent) = obj.parent.as_deref() else {
                continue;
            };
            if !known_principals.contains(parent) {
                return Err(PolicyConfigError::UnknownParent {
                    subject: obj.id.clone(),
                    parent: parent.to_string(),
                });
            }

            // Cycle detection: walk parent links from this object up to a root.
            // If we revisit any object already in the chain, we have a cycle.
            let mut chain: Vec<String> = vec![obj.id.clone()];
            let mut seen: std::collections::HashSet<&str> =
                std::collections::HashSet::from([obj.id.as_str()]);
            let mut cursor: &str = parent;
            loop {
                if !seen.insert(cursor) {
                    chain.push(cursor.to_string());
                    return Err(PolicyConfigError::ParentCycle { chain });
                }
                chain.push(cursor.to_string());
                match parent_of.get(cursor) {
                    Some(next) => cursor = next,
                    None => break,
                }
            }
        }
        Ok(())
    }
}
