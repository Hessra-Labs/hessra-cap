//! Integration tests for the Hessra Capability Engine.

use hessra_cap::{
    CListPolicy, CapabilityEngine, Designation, ExposureLabel, IdentityConfig, MintOptions,
    ObjectId, Operation, PolicyDecision, SessionConfig, TokenTimeConfig,
};

fn test_engine() -> CapabilityEngine<CListPolicy> {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:openclaw"
can_delegate = true
capabilities = [
    { target = "tool:file-read", operations = ["invoke"] },
    { target = "tool:web-search", operations = ["invoke"] },
    { target = "tool:email", operations = ["invoke"] },
    { target = "data:user-profile", operations = ["read"] },
    { target = "data:user-ssn", operations = ["read"] },
    { target = "data:public-info", operations = ["read"] },
]

[[objects]]
id = "service:api-gateway"
can_delegate = false
capabilities = [
    { target = "service:user-service", operations = ["read", "write"] },
]

[[objects]]
id = "agent:jake"
can_delegate = false
capabilities = [
    { target = "filesystem:source", operations = ["read"], anchor_to_subject = true },
]

[[objects]]
id = "service:webapp"
can_delegate = true
capabilities = []

[[objects]]
id = "service:bobapp"
can_delegate = false
capabilities = []

[[objects]]
id = "service:courier-svc"
can_delegate = false
capabilities = [
    { target = "service:bobapp", operations = ["read"], anchor = "service:webapp" },
]

[classifications]
"data:user-profile" = ["PII:email", "PII:address"]
"data:user-ssn" = ["PII:SSN"]

[[exposure_rules]]
labels = ["PII:SSN"]
blocks = ["tool:web-search", "tool:email"]

[[exposure_rules]]
labels = ["PII:*"]
blocks = ["tool:email"]
    "#,
    )
    .expect("Failed to parse test policy");

    CapabilityEngine::with_generated_keys(policy)
}

// =========================================================================
// Basic capability minting and verification
// =========================================================================

#[test]
fn test_mint_and_verify_capability() {
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
        )
        .expect("Should mint capability");

    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        )
        .expect("Should verify capability");
}

#[test]
fn test_mint_denied_no_capability() {
    let engine = test_engine();

    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:delete-everything"),
        &Operation::new("invoke"),
        None,
    );

    assert!(result.is_err());
}

#[test]
fn test_verify_wrong_target_fails() {
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
        )
        .expect("Should mint");

    let verify = engine.verify_capability(
        &result.token,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    );
    assert!(verify.is_err());
}

// =========================================================================
// Context token and exposure tracking
// =========================================================================

#[test]
fn test_mint_context_and_extract_exposure() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    assert!(!context.is_exposed());
    assert!(context.exposure_labels().is_empty());
}

#[test]
fn test_auto_exposure_on_classified_data() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Mint capability for classified data -- should auto-expose the context
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Should mint capability for SSN");

    let updated_context = result.context.expect("Context should be updated");
    assert!(updated_context.is_exposed());
    assert!(updated_context.has_exposure(&ExposureLabel::new("PII:SSN")));
}

#[test]
fn test_no_exposure_for_unclassified_data() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // data:public-info has no classification
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:public-info"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Should mint capability for public info");

    let updated_context = result.context.expect("Context should be returned");
    assert!(!updated_context.is_exposed());
}

#[test]
fn test_exposure_blocks_subsequent_capability() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Step 1: web-search should work before exposure
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_ok());

    // Step 2: Read SSN data (auto-exposes with PII:SSN)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Should mint SSN capability");

    let exposed_context = result.context.expect("Should have updated context");

    // Step 3: web-search should be DENIED with PII:SSN exposure
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&exposed_context),
    );
    assert!(result.is_err());
}

#[test]
fn test_exposure_allows_non_blocked_capabilities() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Expose with SSN
    let exposed = engine
        .add_exposure(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add exposure");

    // file-read should still work with SSN exposure
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        Some(&exposed),
    );
    assert!(result.is_ok());
}

#[test]
fn test_cumulative_exposure() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Add profile exposure (PII:email, PII:address)
    let exposed = engine
        .add_exposure(&context, &ObjectId::new("data:user-profile"))
        .expect("Should add profile exposure");

    assert_eq!(exposed.exposure_labels().len(), 2);

    // Add SSN exposure (PII:SSN) -- should accumulate
    let more_exposed = engine
        .add_exposure(&exposed, &ObjectId::new("data:user-ssn"))
        .expect("Should add SSN exposure");

    assert_eq!(more_exposed.exposure_labels().len(), 3);
    assert!(more_exposed.has_exposure(&ExposureLabel::new("PII:email")));
    assert!(more_exposed.has_exposure(&ExposureLabel::new("PII:address")));
    assert!(more_exposed.has_exposure(&ExposureLabel::new("PII:SSN")));
}

#[test]
fn test_manual_exposure_label() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    let exposed = engine
        .add_exposure_label(
            &context,
            ExposureLabel::new("custom:sensitive"),
            &ObjectId::new("external-system"),
        )
        .expect("Should add custom exposure");

    assert!(exposed.has_exposure(&ExposureLabel::new("custom:sensitive")));
}

// =========================================================================
// Context forking (sub-agent inheritance)
// =========================================================================

#[test]
fn test_fork_context_inherits_exposure() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Expose the parent
    let exposed = engine
        .add_exposure(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add exposure");

    // Fork for sub-agent
    let child_context = engine
        .fork_context(
            &exposed,
            &ObjectId::new("agent:openclaw:subtask-1"),
            SessionConfig::default(),
        )
        .expect("Should fork context");

    // Child should inherit parent's exposure
    assert!(child_context.is_exposed());
    assert!(child_context.has_exposure(&ExposureLabel::new("PII:SSN")));
}

#[test]
fn test_fork_clean_context() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Fork without exposure
    let child_context = engine
        .fork_context(
            &context,
            &ObjectId::new("agent:openclaw:subtask-1"),
            SessionConfig::default(),
        )
        .expect("Should fork context");

    assert!(!child_context.is_exposed());
}

// =========================================================================
// Identity tokens
// =========================================================================

#[test]
fn test_mint_and_verify_identity() {
    let engine = test_engine();

    let token = engine
        .mint_identity(&ObjectId::new("user:alice"), IdentityConfig::default())
        .expect("Should mint identity");

    engine
        .verify_identity(&token, &ObjectId::new("user:alice"))
        .expect("Should verify identity");
}

#[test]
fn test_authenticate_returns_object_id() {
    let engine = test_engine();

    let token = engine
        .mint_identity(&ObjectId::new("user:alice"), IdentityConfig::default())
        .expect("Should mint identity");

    let authenticated = engine.authenticate(&token).expect("Should authenticate");

    assert_eq!(authenticated.as_str(), "user:alice");
}

#[test]
fn test_identity_wrong_identity_fails() {
    let engine = test_engine();

    let token = engine
        .mint_identity(&ObjectId::new("user:alice"), IdentityConfig::default())
        .expect("Should mint identity");

    let result = engine.verify_identity(&token, &ObjectId::new("user:bob"));
    assert!(result.is_err());
}

// =========================================================================
// Policy evaluation without minting
// =========================================================================

#[test]
fn test_evaluate_without_minting() {
    let engine = test_engine();

    let decision = engine.evaluate(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        None,
    );
    assert!(decision.is_granted());

    let decision = engine.evaluate(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:nonexistent"),
        &Operation::new("invoke"),
        None,
    );
    assert!(!decision.is_granted());
}

#[test]
fn test_evaluate_with_exposure() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    let exposed = engine
        .add_exposure(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add exposure");

    let decision = engine.evaluate(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&exposed),
    );
    assert!(!decision.is_granted());
    assert!(matches!(decision, PolicyDecision::DeniedByExposure { .. }));
}

// =========================================================================
// Introspection
// =========================================================================

#[test]
fn test_list_grants() {
    let engine = test_engine();
    let grants = engine.list_grants(&ObjectId::new("agent:openclaw"));
    assert_eq!(grants.len(), 6);
}

#[test]
fn test_can_delegate() {
    let engine = test_engine();
    assert!(engine.can_delegate(&ObjectId::new("agent:openclaw")));
    assert!(!engine.can_delegate(&ObjectId::new("service:api-gateway")));
}

// =========================================================================
// Full agent scenario
// =========================================================================

#[test]
fn test_full_agent_lifecycle() {
    let engine = test_engine();

    // 1. Agent starts a session
    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Session start");

    // 2. Agent reads public data (no exposure)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:public-info"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read public info");
    let context = result.context.expect("Context returned");
    assert!(!context.is_exposed());

    // 3. Agent uses web search (should work, no exposure)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            Some(&context),
        )
        .expect("Web search should work");
    let context = result.context.expect("Context returned");

    // 4. Agent reads user profile (exposed with PII:email, PII:address)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-profile"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read user profile");
    let context = result.context.expect("Context returned with exposure");
    assert!(context.has_exposure(&ExposureLabel::new("PII:email")));

    // 5. Email is now blocked (PII:* blocks tool:email)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:email"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_err(), "Email should be blocked by PII exposure");

    // 6. Web search still works (only PII:SSN blocks it, not PII:email)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(
        result.is_ok(),
        "Web search should still work with PII:email exposure"
    );

    // 7. Agent reads SSN (exposed with PII:SSN)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read SSN");
    let context = result.context.expect("Context returned with more exposure");
    assert!(context.has_exposure(&ExposureLabel::new("PII:SSN")));

    // 8. NOW web search is blocked (PII:SSN blocks tool:web-search)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(
        result.is_err(),
        "Web search should be blocked after SSN exposure"
    );

    // 9. File read still works
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_ok(), "File read should always work");

    // 10. Fork context for sub-agent -- inherits ALL exposure
    let child_context = engine
        .fork_context(
            &context,
            &ObjectId::new("agent:openclaw:subtask"),
            SessionConfig::default(),
        )
        .expect("Fork context");
    assert!(child_context.has_exposure(&ExposureLabel::new("PII:SSN")));
    assert!(child_context.has_exposure(&ExposureLabel::new("PII:email")));
}

// =========================================================================
// Mint capability with options (holder binding, custom time)
// =========================================================================

#[test]
fn test_mint_capability_with_default_options() {
    let engine = test_engine();

    let result = engine
        .mint_capability_with_options(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
            MintOptions::default(),
        )
        .expect("Should mint with default options");

    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        )
        .expect("Should verify");
}

// =========================================================================
// Anchor designation
// =========================================================================
//
// Anchor binds a capability to one named principal as the only authority that
// can verify it. Sub-principals receiving the capability via delegation
// present it back to the anchor for verification. At verify time the verifier
// asserts "I am the anchor" by supplying
// `Designation { label: "anchor", value: <its-own-principal-name> }`. Anchor
// lives in the authority block and survives third-party attenuation.

#[test]
fn test_anchor_via_options_requires_anchor_designation() {
    // mint_capability_with_options + MintOptions { anchor: Some(...), .. }
    // binds the capability even when the policy declaration has no anchor
    // configured.
    let engine = test_engine();

    let result = engine
        .mint_capability_with_options(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
            MintOptions {
                anchor: Some(ObjectId::new("agent:openclaw")),
                ..Default::default()
            },
        )
        .expect("Should mint with explicit anchor option");

    // Non-designated verify path fails closed: no anchor fact supplied.
    let verify = engine.verify_capability(
        &result.token,
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
    );
    assert!(
        verify.is_err(),
        "Anchor-bound cap must fail verification without anchor designation"
    );

    // Verifier asserts "I am agent:openclaw", check passes.
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &[Designation {
                label: "anchor".to_string(),
                value: "agent:openclaw".to_string(),
            }],
        )
        .expect("Should verify when verifier asserts the matching anchor");

    // A different verifier asserting "I am agent:mallory" cannot honor this cap.
    let verify = engine.verify_designated_capability(
        &result.token,
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        &[Designation {
            label: "anchor".to_string(),
            value: "agent:mallory".to_string(),
        }],
    );
    assert!(
        verify.is_err(),
        "Cap must not verify at any principal other than the anchor"
    );
}

#[test]
fn test_anchor_to_subject_resolves_to_subject() {
    // The policy declaration for agent:jake on filesystem:source has
    // anchor_to_subject = true; the engine resolves the anchor to the subject
    // (agent:jake) at mint time.
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            None,
        )
        .expect("Should mint policy-driven anchor capability");

    // Without anchor designation: fails closed.
    let verify = engine.verify_capability(
        &result.token,
        &ObjectId::new("filesystem:source"),
        &Operation::new("read"),
    );
    assert!(
        verify.is_err(),
        "Policy-driven anchor capability must require anchor designation at verify"
    );

    // Jake's own services assert "I am agent:jake" and verify successfully.
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "anchor".to_string(),
                value: "agent:jake".to_string(),
            }],
        )
        .expect("Should verify when anchor matches the subject");
}

#[test]
fn test_explicit_anchor_to_other_principal() {
    // Trustee-style declaration: the issuer mints to courier-svc with the
    // capability anchored at webapp. The courier never had the right to use
    // this capability at any other principal.
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("service:courier-svc"),
            &ObjectId::new("service:bobapp"),
            &Operation::new("read"),
            None,
        )
        .expect("Should mint trustee-style capability");

    // Verifier asserts "I am service:webapp", which is the anchor. Check
    // passes.
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("service:bobapp"),
            &Operation::new("read"),
            &[Designation {
                label: "anchor".to_string(),
                value: "service:webapp".to_string(),
            }],
        )
        .expect("Should verify at the explicit anchor (service:webapp)");

    // The subject cannot honor its own capability by claiming itself as anchor.
    let verify = engine.verify_designated_capability(
        &result.token,
        &ObjectId::new("service:bobapp"),
        &Operation::new("read"),
        &[Designation {
            label: "anchor".to_string(),
            value: "service:courier-svc".to_string(),
        }],
    );
    assert!(
        verify.is_err(),
        "In the trustee pattern, the subject is not the anchor and cannot honor its own capability"
    );
}

#[test]
fn test_anchor_survives_third_party_attenuation() {
    // The anchor check lives in the authority block, so subsequent designation
    // attenuations (which append blocks) cannot strip the anchor binding.
    // This is the delegation pattern: a recipient receives a broad
    // anchor-bound capability, attenuates it per-user, but the resulting
    // capability still must be presented back to the anchor for verification.
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            None,
        )
        .expect("Should mint policy-driven anchor capability");

    // Attenuate with an additional path_prefix designation (third-party block).
    let attenuated = engine
        .attenuate_with_designations(
            &result.token,
            &[Designation {
                label: "path_prefix".to_string(),
                value: "code/hessra/".to_string(),
            }],
        )
        .expect("Should attenuate");

    // Still requires both anchor AND path_prefix at verify time.
    engine
        .verify_designated_capability(
            &attenuated,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[
                Designation {
                    label: "anchor".to_string(),
                    value: "agent:jake".to_string(),
                },
                Designation {
                    label: "path_prefix".to_string(),
                    value: "code/hessra/".to_string(),
                },
            ],
        )
        .expect("Verify with both anchor and path_prefix should succeed");

    // Without anchor designation, attenuated cap still fails.
    let verify = engine.verify_designated_capability(
        &attenuated,
        &ObjectId::new("filesystem:source"),
        &Operation::new("read"),
        &[Designation {
            label: "path_prefix".to_string(),
            value: "code/hessra/".to_string(),
        }],
    );
    assert!(
        verify.is_err(),
        "Anchor check survives attenuation and remains required"
    );
}

#[test]
fn test_non_anchored_declaration_emits_no_anchor_designation() {
    // For declarations without an anchor configuration, mint_capability does
    // NOT add an anchor check. The capability verifies without any
    // designations and can be verified by any principal.
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
        )
        .expect("Should mint plain capability");

    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        )
        .expect("Plain capability should verify with no designations");
}

#[test]
fn test_policy_validation_rejects_anchor_conflict() {
    // anchor_to_subject and anchor on the same declaration must be mutually
    // exclusive.
    let result = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"],
      anchor_to_subject = true, anchor = "service:webapp" },
]

[[objects]]
id = "service:webapp"
capabilities = []
        "#,
    );
    assert!(
        result.is_err(),
        "Policy with both anchor_to_subject and anchor on the same declaration must be rejected"
    );
}

#[test]
fn test_policy_validation_rejects_unknown_anchor_principal() {
    // An explicit anchor must reference a principal declared in the policy.
    let result = CListPolicy::from_toml(
        r#"
[[objects]]
id = "service:courier-svc"
capabilities = [
    { target = "service:bobapp", operations = ["read"],
      anchor = "service:does-not-exist" },
]
        "#,
    );
    assert!(
        result.is_err(),
        "Policy referencing an unknown anchor principal must be rejected"
    );
}

#[test]
fn test_mint_capability_with_custom_time() {
    let engine = test_engine();

    let result = engine
        .mint_capability_with_options(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
            MintOptions {
                time_config: Some(TokenTimeConfig {
                    start_time: None,
                    duration: 600,
                }),
                ..Default::default()
            },
        )
        .expect("Should mint with custom time");

    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        )
        .expect("Should verify with custom time");
}

#[test]
fn test_mint_capability_with_options_denied() {
    let engine = test_engine();

    let result = engine.mint_capability_with_options(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:nonexistent"),
        &Operation::new("invoke"),
        None,
        MintOptions::default(),
    );

    assert!(result.is_err(), "Should be denied for unknown target");
}

#[test]
fn test_mint_capability_with_options_auto_exposes() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    let result = engine
        .mint_capability_with_options(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
            MintOptions::default(),
        )
        .expect("Should mint for classified data");

    let updated_context = result.context.expect("Should have updated context");
    assert!(updated_context.has_exposure(&ExposureLabel::new("PII:SSN")));
}

// =========================================================================
// Designation attenuation
// =========================================================================

#[test]
fn test_attenuate_with_designations() {
    let engine = test_engine();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
        )
        .expect("Should mint capability");

    let designations = vec![Designation {
        label: "tenant_id".to_string(),
        value: "t-123".to_string(),
    }];

    let attenuated = engine
        .attenuate_with_designations(&result.token, &designations)
        .expect("Should attenuate with designations");

    // Verify with matching designation
    engine
        .verify_designated_capability(
            &attenuated,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &designations,
        )
        .expect("Should verify with matching designation");

    // Verify without designation should fail
    let verify = engine.verify_capability(
        &attenuated,
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
    );
    assert!(verify.is_err(), "Should fail without designation");
}

#[test]
fn test_mint_designated_capability() {
    let engine = test_engine();

    let designations = vec![
        Designation {
            label: "tenant_id".to_string(),
            value: "t-123".to_string(),
        },
        Designation {
            label: "user_id".to_string(),
            value: "u-456".to_string(),
        },
    ];

    let result = engine
        .mint_designated_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &designations,
            None,
        )
        .expect("Should mint designated capability");

    // Verify with both designations
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &designations,
        )
        .expect("Should verify designated capability");
}

#[test]
fn test_verify_designated_capability_wrong_designation() {
    let engine = test_engine();

    let designations = vec![Designation {
        label: "tenant_id".to_string(),
        value: "t-123".to_string(),
    }];

    let result = engine
        .mint_designated_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            &designations,
            None,
        )
        .expect("Should mint designated capability");

    // Verify with wrong designation
    let wrong_designations = vec![Designation {
        label: "tenant_id".to_string(),
        value: "t-999".to_string(),
    }];

    let verify = engine.verify_designated_capability(
        &result.token,
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        &wrong_designations,
    );
    assert!(verify.is_err(), "Should fail with wrong designation");
}
