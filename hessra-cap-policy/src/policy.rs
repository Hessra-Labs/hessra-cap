//! CList policy backend implementation.

use std::collections::HashMap;

use hessra_cap_engine::{
    AnchorBinding, Capability, Designation, ExposureLabel, ObjectId, Operation, PolicyBackend,
    PolicyDecision,
};

use crate::config::{ExposureRuleConfig, PolicyConfig};
use crate::matching::matches_pattern;

/// CList (Capability List) policy backend.
///
/// Each object has a capability space listing the targets it can access
/// and the operations it can perform. Data classifications map targets
/// to exposure labels. Exposure rules define which targets are blocked when
/// specific exposure labels are present.
pub struct CListPolicy {
    /// Object capability spaces, keyed by object ID.
    objects: HashMap<String, ObjectEntry>,
    /// Data classifications: target -> exposure labels.
    classifications: HashMap<String, Vec<String>>,
    /// Exposure restriction rules.
    exposure_rules: Vec<ExposureRuleConfig>,
}

struct ObjectEntry {
    can_delegate: bool,
    capabilities: Vec<CapEntry>,
    parent: Option<String>,
}

struct CapEntry {
    target: String,
    operations: Vec<String>,
    anchor: Option<AnchorBinding>,
    designations: Vec<Designation>,
}

impl CListPolicy {
    /// Create a CList policy from a parsed configuration.
    pub fn from_config(config: PolicyConfig) -> Self {
        let mut objects = HashMap::new();

        for obj in config.objects {
            let entry = ObjectEntry {
                can_delegate: obj.can_delegate,
                parent: obj.parent.clone(),
                capabilities: obj
                    .capabilities
                    .into_iter()
                    .map(|c| {
                        // PolicyConfig::validate has already enforced
                        // mutual exclusion of anchor_to_subject and anchor.
                        let anchor = if c.anchor_to_subject {
                            Some(AnchorBinding::Subject)
                        } else {
                            c.anchor.map(|a| AnchorBinding::Principal(ObjectId::new(a)))
                        };
                        let designations = c
                            .designations
                            .into_iter()
                            .map(|d| Designation {
                                label: d.label,
                                value: d.value,
                            })
                            .collect();
                        CapEntry {
                            target: c.target,
                            operations: c.operations,
                            anchor,
                            designations,
                        }
                    })
                    .collect(),
            };
            objects.insert(obj.id, entry);
        }

        Self {
            objects,
            classifications: config.classifications,
            exposure_rules: config.exposure_rules,
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
            exposure_rules: Vec::new(),
        }
    }

    /// The complete set of concrete exposure labels any data source can attest,
    /// derived from the declared classifications. Compound reject rules are
    /// expanded against this universe.
    fn label_universe(&self) -> Vec<String> {
        let mut universe: Vec<String> = Vec::new();
        for labels in self.classifications.values() {
            for label in labels {
                if !universe.contains(label) {
                    universe.push(label.clone());
                }
            }
        }
        universe
    }
}

impl PolicyBackend for CListPolicy {
    fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
    ) -> PolicyDecision {
        // Capability authorization only. Exposure restrictions are enforced at mint
        // time by the context token's reject rules (see `precluding_labels`
        // and `compound_reject_rules`).
        let Some(object) = self.objects.get(subject.as_str()) else {
            return PolicyDecision::Denied {
                reason: format!("object '{subject}' not found in policy"),
            };
        };

        for cap in &object.capabilities {
            if cap.target == target.as_str()
                && cap.operations.iter().any(|op| op == operation.as_str())
            {
                // Resolve AnchorBinding::Subject to the requesting subject so
                // the engine sees a concrete principal.
                let anchor = cap.anchor.as_ref().map(|binding| match binding {
                    AnchorBinding::Subject => subject.clone(),
                    AnchorBinding::Principal(p) => p.clone(),
                });
                return PolicyDecision::Authorized {
                    anchor,
                    designations: cap.designations.clone(),
                };
            }
        }

        PolicyDecision::Denied {
            reason: format!("'{subject}' does not have capability for '{target}'/'{operation}'"),
        }
    }

    fn classification(&self, target: &ObjectId) -> Vec<ExposureLabel> {
        self.classifications
            .get(target.as_str())
            .map(|labels| {
                labels
                    .iter()
                    .map(|l| ExposureLabel::new(l.as_str()))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn precluding_labels(
        &self,
        target: &ObjectId,
        attested: &[ExposureLabel],
    ) -> Vec<ExposureLabel> {
        let mut out: Vec<ExposureLabel> = Vec::new();
        if attested.is_empty() {
            return out;
        }

        let push_unique = |label: &ExposureLabel, out: &mut Vec<ExposureLabel>| {
            if !out.contains(label) {
                out.push(label.clone());
            }
        };

        for rule in &self.exposure_rules {
            // Only rules that block this target contribute candidate facts.
            if !rule
                .blocks
                .iter()
                .any(|blocked| matches_pattern(blocked, target.as_str()))
            {
                continue;
            }

            if rule.r#match == "all" {
                // Conjunction: contribute the rule's matching attested labels
                // only when every pattern is satisfied by some attested label.
                // The token's compound reject enforces the AND; gating here
                // keeps a single member from tripping a per-label reject meant
                // for a different target.
                let all_matched = rule.labels.iter().all(|pattern| {
                    attested
                        .iter()
                        .any(|label| matches_pattern(pattern, label.as_str()))
                });
                if !all_matched {
                    continue;
                }
            }

            // "any" rules (and satisfied "all" rules) contribute every attested
            // label that matches one of their patterns.
            for label in attested {
                let matches = rule
                    .labels
                    .iter()
                    .any(|pattern| matches_pattern(pattern, label.as_str()));
                if matches {
                    push_unique(label, &mut out);
                }
            }
        }

        out
    }

    fn compound_reject_rules(&self) -> Vec<(ExposureLabel, ExposureLabel)> {
        let universe = self.label_universe();
        let expand = |pattern: &str| -> Vec<String> {
            universe
                .iter()
                .filter(|label| matches_pattern(pattern, label))
                .cloned()
                .collect()
        };

        let mut pairs: Vec<(ExposureLabel, ExposureLabel)> = Vec::new();
        for rule in &self.exposure_rules {
            if rule.r#match != "all" {
                continue;
            }
            if rule.labels.len() != 2 {
                tracing::warn!(
                    labels = ?rule.labels,
                    "compound exposure rule has {} labels; only two-label compound \
                     rules are enforced under reject-if, skipping",
                    rule.labels.len()
                );
                continue;
            }
            for first in expand(&rule.labels[0]) {
                for second in expand(&rule.labels[1]) {
                    if first == second {
                        continue;
                    }
                    let pair = (ExposureLabel::new(&first), ExposureLabel::new(&second));
                    let dup = pairs.iter().any(|(a, b)| {
                        (*a == pair.0 && *b == pair.1) || (*a == pair.1 && *b == pair.0)
                    });
                    if !dup {
                        pairs.push(pair);
                    }
                }
            }
        }
        pairs
    }

    fn list_capabilities(&self, subject: &ObjectId) -> Vec<Capability> {
        self.objects
            .get(subject.as_str())
            .map(|obj| {
                obj.capabilities
                    .iter()
                    .map(|cap| Capability {
                        target: ObjectId::new(&cap.target),
                        operations: cap.operations.iter().map(Operation::new).collect(),
                        anchor: cap.anchor.clone(),
                        designations: cap.designations.clone(),
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

    fn parent(&self, subject: &ObjectId) -> Option<ObjectId> {
        self.objects
            .get(subject.as_str())
            .and_then(|obj| obj.parent.as_deref().map(ObjectId::new))
    }

    fn all_capabilities(&self) -> Vec<(ObjectId, Capability)> {
        let mut result = Vec::new();
        for (subject, obj) in &self.objects {
            for cap in &obj.capabilities {
                result.push((
                    ObjectId::new(subject.as_str()),
                    Capability {
                        target: ObjectId::new(&cap.target),
                        operations: cap.operations.iter().map(Operation::new).collect(),
                        anchor: cap.anchor.clone(),
                        designations: cap.designations.clone(),
                    },
                ));
            }
        }
        result
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

[[exposure_rules]]
labels = ["PII:SSN"]
blocks = ["tool:external-api", "tool:email", "tool:web-search"]

[[exposure_rules]]
labels = ["PII:*", "financial:*"]
match = "all"
blocks = ["tool:*"]
        "#;

        CListPolicy::from_toml(toml).expect("Failed to parse test policy")
    }

    #[test]
    fn test_basic_capability() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        );
        assert!(decision.is_authorized());
    }

    #[test]
    fn test_denied_no_capability() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:delete-everything"),
            &Operation::new("invoke"),
        );
        assert!(!decision.is_authorized());
    }

    #[test]
    fn test_denied_wrong_operation() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("service:api-gateway"),
            &ObjectId::new("service:user-service"),
            &Operation::new("delete"),
        );
        assert!(!decision.is_authorized());
    }

    #[test]
    fn test_denied_unknown_subject() {
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:unknown"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        );
        assert!(!decision.is_authorized());
    }

    #[test]
    fn test_evaluate_ignores_exposure() {
        // evaluate decides authorization only; exposure no longer factors in.
        let policy = test_policy();
        let decision = policy.evaluate(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
        );
        assert!(decision.is_authorized());
    }

    #[test]
    fn test_precluding_labels_single_label_rule() {
        let policy = test_policy();
        let attested = vec![ExposureLabel::new("PII:SSN")];

        // tool:web-search is blocked by the single-label PII:SSN rule.
        let precluding = policy.precluding_labels(&ObjectId::new("tool:web-search"), &attested);
        assert_eq!(precluding, vec![ExposureLabel::new("PII:SSN")]);

        // tool:file-read is not blocked by that rule -> nothing to assert.
        let precluding = policy.precluding_labels(&ObjectId::new("tool:file-read"), &attested);
        assert!(precluding.is_empty());
    }

    #[test]
    fn test_precluding_labels_compound_rule_gating() {
        let policy = test_policy();

        // The compound rule (PII:* AND financial:*) blocks tool:*. A single
        // member must not contribute candidate facts.
        let pii_only = vec![ExposureLabel::new("PII:email")];
        let precluding = policy.precluding_labels(&ObjectId::new("tool:file-read"), &pii_only);
        assert!(
            precluding.is_empty(),
            "a single compound member must not be asserted"
        );

        // Both members present -> contribute both matching attested labels.
        let both = vec![
            ExposureLabel::new("PII:email"),
            ExposureLabel::new("financial:balance"),
        ];
        let precluding = policy.precluding_labels(&ObjectId::new("tool:file-read"), &both);
        assert!(precluding.contains(&ExposureLabel::new("PII:email")));
        assert!(precluding.contains(&ExposureLabel::new("financial:balance")));
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
    fn test_list_capabilities() {
        let policy = test_policy();
        let caps = policy.list_capabilities(&ObjectId::new("agent:openclaw"));
        assert_eq!(caps.len(), 5);
    }

    #[test]
    fn test_can_delegate() {
        let policy = test_policy();
        assert!(policy.can_delegate(&ObjectId::new("agent:openclaw")));
        assert!(!policy.can_delegate(&ObjectId::new("service:api-gateway")));
        assert!(!policy.can_delegate(&ObjectId::new("unknown")));
    }
}
