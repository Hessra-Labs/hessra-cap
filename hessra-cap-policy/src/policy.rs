//! CList policy backend implementation.

use std::collections::HashMap;

use hessra_cap_engine::{
    CapabilityGrant, ObjectId, Operation, PolicyBackend, PolicyDecision, TaintLabel,
};

use crate::config::{PolicyConfig, TaintRuleConfig};
use crate::matching::matches_pattern;

/// CList (Capability List) policy backend.
///
/// Each object has a capability space listing the targets it can access
/// and the operations it can perform. Data classifications map targets
/// to taint labels. Taint rules define which targets are blocked when
/// specific taint labels are present.
pub struct CListPolicy {
    /// Object capability spaces, keyed by object ID.
    objects: HashMap<String, ObjectEntry>,
    /// Data classifications: target -> taint labels.
    classifications: HashMap<String, Vec<String>>,
    /// Taint restriction rules.
    taint_rules: Vec<TaintRuleConfig>,
}

struct ObjectEntry {
    can_delegate: bool,
    capabilities: Vec<CapEntry>,
}

struct CapEntry {
    target: String,
    operations: Vec<String>,
}

impl CListPolicy {
    /// Create a CList policy from a parsed configuration.
    pub fn from_config(config: PolicyConfig) -> Self {
        let mut objects = HashMap::new();

        for obj in config.objects {
            let entry = ObjectEntry {
                can_delegate: obj.can_delegate,
                capabilities: obj
                    .capabilities
                    .into_iter()
                    .map(|c| CapEntry {
                        target: c.target,
                        operations: c.operations,
                    })
                    .collect(),
            };
            objects.insert(obj.id, entry);
        }

        Self {
            objects,
            classifications: config.classifications,
            taint_rules: config.taint_rules,
        }
    }

    /// Create a CList policy from a TOML string.
    pub fn from_toml(content: &str) -> Result<Self, crate::config::PolicyConfigError> {
        let config = PolicyConfig::parse(content)?;
        Ok(Self::from_config(config))
    }

    /// Create a CList policy from a TOML file.
    pub fn from_file(path: &std::path::Path) -> Result<Self, crate::config::PolicyConfigError> {
        let config = PolicyConfig::from_file(path)?;
        Ok(Self::from_config(config))
    }

    /// Create an empty policy (useful for testing).
    pub fn empty() -> Self {
        Self {
            objects: HashMap::new(),
            classifications: HashMap::new(),
            taint_rules: Vec::new(),
        }
    }

    /// Check if any taint rule blocks access to a target given the current taint labels.
    fn check_taint_restrictions(
        &self,
        target: &str,
        taint_labels: &[TaintLabel],
    ) -> Option<(TaintLabel, ObjectId)> {
        if taint_labels.is_empty() {
            return None;
        }

        for rule in &self.taint_rules {
            let rule_matches = if rule.r#match == "all" {
                // All label patterns must match at least one taint label
                rule.labels.iter().all(|pattern| {
                    taint_labels
                        .iter()
                        .any(|label| matches_pattern(pattern, label.as_str()))
                })
            } else {
                // Any label pattern matches any taint label
                rule.labels.iter().any(|pattern| {
                    taint_labels
                        .iter()
                        .any(|label| matches_pattern(pattern, label.as_str()))
                })
            };

            if rule_matches {
                // Check if the target is in the blocked list
                for blocked in &rule.blocks {
                    if matches_pattern(blocked, target) {
                        // Find the first matching taint label for the error
                        let matching_label = taint_labels
                            .iter()
                            .find(|label| {
                                rule.labels
                                    .iter()
                                    .any(|pattern| matches_pattern(pattern, label.as_str()))
                            })
                            .cloned()
                            .unwrap_or_else(|| TaintLabel::new("unknown"));

                        return Some((matching_label, ObjectId::new(target)));
                    }
                }
            }
        }

        None
    }
}

impl PolicyBackend for CListPolicy {
    fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        taint_labels: &[TaintLabel],
    ) -> PolicyDecision {
        // Step 1: Check taint restrictions first
        if let Some((label, blocked_target)) =
            self.check_taint_restrictions(target.as_str(), taint_labels)
        {
            return PolicyDecision::DeniedByTaint {
                label,
                blocked_target,
            };
        }

        // Step 2: Check capability space
        let Some(object) = self.objects.get(subject.as_str()) else {
            return PolicyDecision::Denied {
                reason: format!("object '{subject}' not found in policy"),
            };
        };

        for cap in &object.capabilities {
            if cap.target == target.as_str()
                && cap.operations.iter().any(|op| op == operation.as_str())
            {
                return PolicyDecision::Granted;
            }
        }

        PolicyDecision::Denied {
            reason: format!("'{subject}' does not have capability for '{target}'/'{operation}'"),
        }
    }

    fn classification(&self, target: &ObjectId) -> Vec<TaintLabel> {
        self.classifications
            .get(target.as_str())
            .map(|labels| labels.iter().map(|l| TaintLabel::new(l.as_str())).collect())
            .unwrap_or_default()
    }

    fn list_grants(&self, subject: &ObjectId) -> Vec<CapabilityGrant> {
        self.objects
            .get(subject.as_str())
            .map(|obj| {
                obj.capabilities
                    .iter()
                    .map(|cap| CapabilityGrant {
                        target: ObjectId::new(&cap.target),
                        operations: cap.operations.iter().map(Operation::new).collect(),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn can_delegate(&self, subject: &ObjectId) -> bool {
        self.objects
            .get(subject.as_str())
            .map(|obj| obj.can_delegate)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> CListPolicy {
        let toml = r#"
[[objects]]
id = "agent:openclaw"
can_delegate = true
capabilities = [
    { target = "tool:file-read", operations = ["invoke"] },
    { target = "tool:web-search", operations = ["invoke"] },
    { target = "tool:email", operations = ["invoke"] },
    { target = "data:user-profile", operations = ["read"] },
    { target = "data:user-ssn", operations = ["read"] },
]

[[objects]]
id = "service:api-gateway"
can_delegate = false
capabilities = [
    { target = "service:user-service", operations = ["read", "write"] },
]

[classifications]
"data:user-profile" = ["PII:email", "PII:address"]
"data:user-ssn" = ["PII:SSN"]

[[taint_rules]]
labels = ["PII:SSN"]
blocks = ["tool:external-api", "tool:email", "tool:web-search"]

[[taint_rules]]
labels = ["PII:*", "financial:*"]
match = "all"
blocks = ["tool:*"]
        "#;

        CListPolicy::from_toml(toml).expect("Failed to parse test policy")
    }

    #[test]
    fn test_basic_grant() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &[],
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn test_denied_no_capability() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:delete-everything"),
            &Operation::new("invoke"),
            &[],
        );
        assert!(!decision.is_granted());
    }

    #[test]
    fn test_denied_wrong_operation() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("service:api-gateway"),
            &ObjectId::new("service:user-service"),
            &Operation::new("delete"),
            &[],
        );
        assert!(!decision.is_granted());
    }

    #[test]
    fn test_denied_unknown_subject() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:unknown"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &[],
        );
        assert!(!decision.is_granted());
    }

    #[test]
    fn test_taint_blocks_access() {
        let policy = test_policy();
        let taint = vec![TaintLabel::new("PII:SSN")];

        // web-search should be blocked
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            &taint,
        );
        assert!(!decision.is_granted());
        assert!(matches!(decision, PolicyDecision::DeniedByTaint { .. }));
    }

    #[test]
    fn test_taint_allows_non_blocked() {
        let policy = test_policy();
        let taint = vec![TaintLabel::new("PII:SSN")];

        // file-read should still work with SSN taint
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &taint,
        );
        assert!(decision.is_granted());
    }

    #[test]
    fn test_compound_taint_rule() {
        let policy = test_policy();

        // PII alone shouldn't trigger the compound rule
        let pii_only = vec![TaintLabel::new("PII:email")];
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &pii_only,
        );
        assert!(decision.is_granted());

        // PII + financial should trigger the compound rule blocking all tools
        let both = vec![
            TaintLabel::new("PII:email"),
            TaintLabel::new("financial:balance"),
        ];
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &both,
        );
        assert!(!decision.is_granted());
    }

    #[test]
    fn test_classification_lookup() {
        let policy = test_policy();

        let labels = policy.classification(&ObjectId::new("data:user-ssn"));
        assert_eq!(labels.len(), 1);
        assert_eq!(labels[0].as_str(), "PII:SSN");

        let labels = policy.classification(&ObjectId::new("data:user-profile"));
        assert_eq!(labels.len(), 2);

        let labels = policy.classification(&ObjectId::new("data:unclassified"));
        assert!(labels.is_empty());
    }

    #[test]
    fn test_list_grants() {
        let policy = test_policy();
        let grants = policy.list_grants(&ObjectId::new("agent:openclaw"));
        assert_eq!(grants.len(), 5);
    }

    #[test]
    fn test_can_delegate() {
        let policy = test_policy();
        assert!(policy.can_delegate(&ObjectId::new("agent:openclaw")));
        assert!(!policy.can_delegate(&ObjectId::new("service:api-gateway")));
        assert!(!policy.can_delegate(&ObjectId::new("unknown")));
    }
}
