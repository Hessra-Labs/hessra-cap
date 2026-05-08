//! Integration tests for the delegated identity chain check at mint time.

use hessra_cap::{
    CListPolicy, CapabilityEngine, EngineError, ObjectId, Operation, PolicyConfigError,
};

#[test]
fn sub_identity_with_matching_grant_succeeds_when_parent_has_grant() {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]

[[objects]]
id = "user:jake:ci_cd"
parent = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    engine
        .mint_capability(
            &ObjectId::new("user:jake:ci_cd"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("sub-identity mint succeeds when parent has the grant too");
}

#[test]
fn sub_identity_fails_when_parent_lacks_grant() {
    // Sub-identity has the grant but its parent doesn't. Mint must fail.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake"
capabilities = []

[[objects]]
id = "user:jake:ci_cd"
parent = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    let err = match engine.mint_capability(
        &ObjectId::new("user:jake:ci_cd"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        None,
    ) {
        Ok(_) => panic!("expected chain check to fail"),
        Err(e) => e,
    };

    match err {
        EngineError::ChainCheckFailed {
            subject,
            ancestor,
            target,
            ..
        } => {
            assert_eq!(subject.as_str(), "user:jake:ci_cd");
            assert_eq!(ancestor.as_str(), "user:jake");
            assert_eq!(target.as_str(), "tool:web-search");
        }
        other => panic!("wrong error: {other:?}"),
    }
}

#[test]
fn transitive_chain_walk_catches_grandparent_missing_grant() {
    // Three-level chain. Both immediate parent and the grandchild have the
    // grant; the root does not. The chain walk reaches the root and fails.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:org"
capabilities = []

[[objects]]
id = "user:org:dept"
parent = "user:org"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]

[[objects]]
id = "user:org:dept:alice"
parent = "user:org:dept"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    let err = match engine.mint_capability(
        &ObjectId::new("user:org:dept:alice"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        None,
    ) {
        Ok(_) => panic!("expected grandparent miss"),
        Err(e) => e,
    };

    match err {
        EngineError::ChainCheckFailed { ancestor, .. } => {
            assert_eq!(ancestor.as_str(), "user:org");
        }
        other => panic!("wrong error: {other:?}"),
    }
}

#[test]
fn root_principal_unaffected_by_chain_check() {
    // No parent declared; chain walk is a no-op. Mint succeeds as before.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:openclaw"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("root principal mint succeeds without chain check effect");
}

#[test]
fn removing_parent_grant_revokes_descendants_on_next_mint() {
    // Demonstrates transitive revocation. With the parent's grant present
    // both mint. Reload the policy without the parent's grant: the
    // descendant's mint now fails even though its own grant is still there.

    let policy_with_parent_grant = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]

[[objects]]
id = "user:jake:ci_cd"
parent = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy_with_parent_grant);
    engine
        .mint_capability(
            &ObjectId::new("user:jake:ci_cd"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("first mint succeeds");

    // Now load a new policy with the parent's grant removed.
    let policy_without_parent_grant = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake"
capabilities = []

[[objects]]
id = "user:jake:ci_cd"
parent = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy_without_parent_grant);
    let err = match engine.mint_capability(
        &ObjectId::new("user:jake:ci_cd"),
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
        None,
    ) {
        Ok(_) => panic!("expected revocation to bite"),
        Err(e) => e,
    };
    assert!(
        matches!(err, EngineError::ChainCheckFailed { .. }),
        "expected ChainCheckFailed, got {err:?}",
    );
}

#[test]
fn policy_load_rejects_unknown_parent() {
    let result = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake:ci_cd"
parent = "user:never-declared"
"#,
    );

    let err = match result {
        Ok(_) => panic!("expected unknown parent to fail at load"),
        Err(e) => e,
    };
    assert!(
        matches!(err, PolicyConfigError::UnknownParent { .. }),
        "expected UnknownParent, got {err:?}",
    );
}

#[test]
fn policy_load_rejects_parent_cycle() {
    let result = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:a"
parent = "user:b"

[[objects]]
id = "user:b"
parent = "user:a"
"#,
    );

    let err = match result {
        Ok(_) => panic!("expected cycle detection"),
        Err(e) => e,
    };
    assert!(
        matches!(err, PolicyConfigError::ParentCycle { .. }),
        "expected ParentCycle, got {err:?}",
    );
}

#[test]
fn parent_independent_of_can_delegate() {
    // A parent with `can_delegate = false` can still have children, and the
    // chain check works exactly the same way. `can_delegate` and `parent`
    // are independent concerns.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "user:jake"
can_delegate = false
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]

[[objects]]
id = "user:jake:ci_cd"
parent = "user:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    engine
        .mint_capability(
            &ObjectId::new("user:jake:ci_cd"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint succeeds regardless of parent's can_delegate");
}
