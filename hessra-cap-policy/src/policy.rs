//! CList policy backend implementation.

use std::collections::HashMap;

use hessra_cap_engine::{
    AnchorBinding, Capability, Designation, ExposureLabel, ObjectId, Operation, PolicyBackend,
    PolicyDecision, compound_label, compound_members,
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
                // Conjunction: contribute the synthesized compound label, not
                // its members. The compound only exists as a reject rule if the
                // session actually satisfied the conjunction, so asserting it
                // cannot trip a per-label reject meant for a different target --
                // the hazard the old member-gating had to work around.
                //
                // Restricted to compounds already attested: this is the gather
                // step, not the conferral step, and a conjunction that has not
                // been conferred yet must not block.
                for label in self.satisfied_compound_labels(attested) {
                    if attested.contains(&label) {
                        push_unique(&label, &mut out);
                    }
                }
                continue;
            }

            // "any" rules contribute every attested label matching a pattern.
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

    fn satisfied_compound_labels(&self, attested: &[ExposureLabel]) -> Vec<ExposureLabel> {
        let mut out: Vec<ExposureLabel> = Vec::new();
        if attested.is_empty() {
            return out;
        }

        for rule in &self.exposure_rules {
            if rule.r#match != "all" || rule.labels.len() < 2 {
                continue;
            }

            // One bucket of concrete attested labels per pattern. A pattern
            // nothing matches means the conjunction has not occurred, so the
            // rule contributes nothing.
            //
            // Compounds already in `attested` are excluded as members: a
            // conjunction is over the plain labels a session actually holds,
            // and letting a compound stand in for its own member would build
            // `a&(a&b)`-shaped nonsense.
            let mut buckets: Vec<Vec<&str>> = Vec::with_capacity(rule.labels.len());
            for pattern in &rule.labels {
                let bucket: Vec<&str> = attested
                    .iter()
                    .map(|l| l.as_str())
                    .filter(|l| compound_members(l).is_none())
                    .filter(|l| matches_pattern(pattern, l))
                    .collect();
                if bucket.is_empty() {
                    break;
                }
                buckets.push(bucket);
            }
            if buckets.len() != rule.labels.len() {
                continue;
            }

            // Cross-product over the buckets. Bounded by what the session has
            // actually been exposed to, not by the classification universe --
            // which is the whole reason this replaced a mint-time expansion.
            let mut combos: Vec<Vec<&str>> = vec![Vec::new()];
            for bucket in &buckets {
                let mut next = Vec::with_capacity(combos.len() * bucket.len());
                for combo in &combos {
                    for label in bucket {
                        let mut extended = combo.clone();
                        extended.push(label);
                        next.push(extended);
                    }
                }
                combos = next;
            }

            for combo in combos {
                // `compound_label` sorts and dedupes, so distinct combinations
                // that name the same set collapse here. It errors when fewer
                // than two distinct members remain -- a combination that picked
                // the same label for every pattern -- which is not a
                // conjunction and is correctly skipped.
                let Ok(label) = compound_label(&combo) else {
                    continue;
                };
                let label = ExposureLabel::new(&label);
                if !out.contains(&label) {
                    out.push(label);
                }
            }
        }
        out
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
    fn test_compound_rule_synthesizes_then_precludes() {
        let policy = test_policy();

        // The compound rule (PII:* AND financial:*) blocks tool:*.
        // One member: no conjunction, nothing synthesized, nothing blocked.
        let pii_only = vec![ExposureLabel::new("PII:email")];
        assert!(policy.satisfied_compound_labels(&pii_only).is_empty());
        assert!(
            policy
                .precluding_labels(&ObjectId::new("tool:file-read"), &pii_only)
                .is_empty(),
            "a single compound member must not block"
        );

        // Both members: the conjunction is satisfied, so a compound label is
        // synthesized from the concrete labels that matched.
        let both = vec![
            ExposureLabel::new("PII:email"),
            ExposureLabel::new("financial:balance"),
        ];
        let synthesized = policy.satisfied_compound_labels(&both);
        let expected = ExposureLabel::new(
            compound_label(&["PII:email", "financial:balance"]).expect("compound"),
        );
        assert_eq!(synthesized, vec![expected.clone()]);

        // Synthesized but not yet conferred -> still nothing to assert. The
        // gather step reads the context; it does not write it.
        assert!(
            policy
                .precluding_labels(&ObjectId::new("tool:file-read"), &both)
                .is_empty(),
            "an unconferred conjunction must not block"
        );

        // Once conferred, the compound is what gets asserted -- not its members.
        let mut attested = both.clone();
        attested.push(expected.clone());
        let precluding = policy.precluding_labels(&ObjectId::new("tool:file-read"), &attested);
        assert_eq!(precluding, vec![expected]);
    }

    #[test]
    fn test_compound_rule_crosses_only_attested_labels() {
        // The old encoding expanded patterns against the whole classification
        // universe at mint. Synthesis crosses only what the session actually
        // holds, so two matches on one side yield two compounds -- not the
        // universe-sized product.
        let policy = test_policy();

        let attested = vec![
            ExposureLabel::new("PII:email"),
            ExposureLabel::new("financial:balance"),
            ExposureLabel::new("financial:card"),
        ];
        let synthesized = policy.satisfied_compound_labels(&attested);
        assert_eq!(synthesized.len(), 2, "got {synthesized:?}");
        for other in ["financial:balance", "financial:card"] {
            let want = ExposureLabel::new(compound_label(&["PII:email", other]).expect("compound"));
            assert!(synthesized.contains(&want), "missing {want:?}");
        }
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
