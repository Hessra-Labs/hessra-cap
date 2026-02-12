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
}

/// Top-level policy configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct PolicyConfig {
    /// Objects and their capability spaces.
    #[serde(default)]
    pub objects: Vec<ObjectConfig>,

    /// Data classifications: maps target object IDs to taint labels.
    #[serde(default)]
    pub classifications: HashMap<String, Vec<String>>,

    /// Taint restriction rules.
    #[serde(default)]
    pub taint_rules: Vec<TaintRuleConfig>,
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

/// A single capability grant configuration.
#[derive(Debug, Clone, Deserialize)]
pub struct CapabilityConfig {
    /// The target object ID (e.g., "service:user-service", "tool:web-search").
    pub target: String,
    /// Allowed operations on the target (e.g., ["read", "write"]).
    pub operations: Vec<String>,
}

/// A taint restriction rule.
#[derive(Debug, Clone, Deserialize)]
pub struct TaintRuleConfig {
    /// Taint labels that trigger this rule. Supports glob patterns (e.g., "PII:*").
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
        Ok(config)
    }
}
