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
// Mint capability with options (namespace restriction, custom time)
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

#[test]
fn test_mint_capability_with_namespace_restriction() {
    let engine = test_engine();

    let result = engine
        .mint_capability_with_options(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
            MintOptions {
                namespace: Some("myapp.hessra.dev".to_string()),
                ..Default::default()
            },
        )
        .expect("Should mint with namespace");

    // Namespace-restricted token should fail without namespace fact
    let verify = engine.verify_capability(
        &result.token,
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
    );
    assert!(verify.is_err(), "Should fail without namespace in verifier");
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
