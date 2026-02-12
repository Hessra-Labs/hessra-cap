//! Integration tests for the Hessra Capability Engine.

use hessra_cap_engine::{
    CapabilityEngine, IdentityConfig, ObjectId, Operation, PolicyDecision, SessionConfig,
    TaintLabel,
};
use hessra_cap_policy::CListPolicy;

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

[[taint_rules]]
labels = ["PII:SSN"]
blocks = ["tool:web-search", "tool:email"]

[[taint_rules]]
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
// Context token and taint tracking
// =========================================================================

#[test]
fn test_mint_context_and_extract_taint() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    assert!(!context.is_tainted());
    assert!(context.taint_labels().is_empty());
}

#[test]
fn test_auto_taint_on_classified_data() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Mint capability for classified data -- should auto-taint the context
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Should mint capability for SSN");

    let updated_context = result.context.expect("Context should be updated");
    assert!(updated_context.is_tainted());
    assert!(updated_context.has_taint(&TaintLabel::new("PII:SSN")));
}

#[test]
fn test_no_taint_for_unclassified_data() {
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
    assert!(!updated_context.is_tainted());
}

#[test]
fn test_taint_blocks_subsequent_capability() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Step 1: web-search should work before taint
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_ok());

    // Step 2: Read SSN data (auto-taints with PII:SSN)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Should mint SSN capability");

    let tainted_context = result.context.expect("Should have updated context");

    // Step 3: web-search should be DENIED with PII:SSN taint
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&tainted_context),
    );
    assert!(result.is_err());
}

#[test]
fn test_taint_allows_non_blocked_capabilities() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Taint with SSN
    let tainted = engine
        .add_taint(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add taint");

    // file-read should still work with SSN taint
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        Some(&tainted),
    );
    assert!(result.is_ok());
}

#[test]
fn test_cumulative_taint() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Add profile taint (PII:email, PII:address)
    let tainted = engine
        .add_taint(&context, &ObjectId::new("data:user-profile"))
        .expect("Should add profile taint");

    assert_eq!(tainted.taint_labels().len(), 2);

    // Add SSN taint (PII:SSN) -- should accumulate
    let more_tainted = engine
        .add_taint(&tainted, &ObjectId::new("data:user-ssn"))
        .expect("Should add SSN taint");

    assert_eq!(more_tainted.taint_labels().len(), 3);
    assert!(more_tainted.has_taint(&TaintLabel::new("PII:email")));
    assert!(more_tainted.has_taint(&TaintLabel::new("PII:address")));
    assert!(more_tainted.has_taint(&TaintLabel::new("PII:SSN")));
}

#[test]
fn test_manual_taint_label() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    let tainted = engine
        .add_taint_label(
            &context,
            TaintLabel::new("custom:sensitive"),
            &ObjectId::new("external-system"),
        )
        .expect("Should add custom taint");

    assert!(tainted.has_taint(&TaintLabel::new("custom:sensitive")));
}

// =========================================================================
// Context forking (sub-agent inheritance)
// =========================================================================

#[test]
fn test_fork_context_inherits_taint() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Taint the parent
    let tainted = engine
        .add_taint(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add taint");

    // Fork for sub-agent
    let child_context = engine
        .fork_context(
            &tainted,
            &ObjectId::new("agent:openclaw:subtask-1"),
            SessionConfig::default(),
        )
        .expect("Should fork context");

    // Child should inherit parent's taint
    assert!(child_context.is_tainted());
    assert!(child_context.has_taint(&TaintLabel::new("PII:SSN")));
}

#[test]
fn test_fork_clean_context() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    // Fork without taint
    let child_context = engine
        .fork_context(
            &context,
            &ObjectId::new("agent:openclaw:subtask-1"),
            SessionConfig::default(),
        )
        .expect("Should fork context");

    assert!(!child_context.is_tainted());
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
fn test_evaluate_with_taint() {
    let engine = test_engine();

    let context = engine
        .mint_context(&ObjectId::new("agent:openclaw"), SessionConfig::default())
        .expect("Should mint context");

    let tainted = engine
        .add_taint(&context, &ObjectId::new("data:user-ssn"))
        .expect("Should add taint");

    let decision = engine.evaluate(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&tainted),
    );
    assert!(!decision.is_granted());
    assert!(matches!(decision, PolicyDecision::DeniedByTaint { .. }));
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

    // 2. Agent reads public data (no taint)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:public-info"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read public info");
    let context = result.context.expect("Context returned");
    assert!(!context.is_tainted());

    // 3. Agent uses web search (should work, no taint)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            Some(&context),
        )
        .expect("Web search should work");
    let context = result.context.expect("Context returned");

    // 4. Agent reads user profile (tainted with PII:email, PII:address)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-profile"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read user profile");
    let context = result.context.expect("Context returned with taint");
    assert!(context.has_taint(&TaintLabel::new("PII:email")));

    // 5. Email is now blocked (PII:* blocks tool:email)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:email"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_err(), "Email should be blocked by PII taint");

    // 6. Web search still works (only PII:SSN blocks it, not PII:email)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(
        result.is_ok(),
        "Web search should still work with PII:email taint"
    );

    // 7. Agent reads SSN (tainted with PII:SSN)
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("data:user-ssn"),
            &Operation::new("read"),
            Some(&context),
        )
        .expect("Read SSN");
    let context = result.context.expect("Context returned with more taint");
    assert!(context.has_taint(&TaintLabel::new("PII:SSN")));

    // 8. NOW web search is blocked (PII:SSN blocks tool:web-search)
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(
        result.is_err(),
        "Web search should be blocked after SSN taint"
    );

    // 9. File read still works
    let result = engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("tool:file-read"),
        &Operation::new("invoke"),
        Some(&context),
    );
    assert!(result.is_ok(), "File read should always work");

    // 10. Fork context for sub-agent -- inherits ALL taint
    let child_context = engine
        .fork_context(
            &context,
            &ObjectId::new("agent:openclaw:subtask"),
            SessionConfig::default(),
        )
        .expect("Fork context");
    assert!(child_context.has_taint(&TaintLabel::new("PII:SSN")));
    assert!(child_context.has_taint(&TaintLabel::new("PII:email")));
}
