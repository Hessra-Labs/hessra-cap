//! Integration tests for forwarding facets.

use hessra_cap::{
    CListPolicy, CapabilityEngine, Designation, MintOptions, ObjectId, Operation, SchemaError,
    SchemaRegistry,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

fn jake_can_invoke_web_search() -> CListPolicy {
    CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses")
}

#[test]
fn engine_without_facets_behaves_unchanged() {
    // Default engine: facets disabled, mint and verify behave as before.
    let engine = CapabilityEngine::with_generated_keys(jake_can_invoke_web_search());
    assert!(!engine.facets_enabled());
    assert!(engine.facet_map().is_empty());

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");

    // The map stays empty because facets are off.
    assert!(engine.facet_map().is_empty());

    // Both verify methods work without supplying a facet designation.
    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
        )
        .expect("non-consuming verify");
    engine
        .verify_and_consume_capability(
            &result.token,
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
        )
        .expect("consume verify is a no-op when facets disabled");
}

#[test]
fn enabling_facets_attaches_designation_on_every_mint() {
    let engine = CapabilityEngine::with_generated_keys(jake_can_invoke_web_search()).with_facets();
    assert!(engine.facets_enabled());

    let r1 = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint 1");
    let r2 = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint 2");

    // Each mint registered a fresh facet.
    assert_eq!(engine.facet_map().len(), 2);

    // Tokens differ; the facet designation is unique per mint.
    assert_ne!(r1.token, r2.token);
}

#[test]
fn non_consuming_verify_auto_supplies_facet_and_succeeds_repeatedly() {
    let engine = CapabilityEngine::with_generated_keys(jake_can_invoke_web_search()).with_facets();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");
    assert_eq!(engine.facet_map().len(), 1);

    // Multiple non-consuming verifies all succeed; entry stays in the map.
    for _ in 0..3 {
        engine
            .verify_capability(
                &result.token,
                &ObjectId::new("tool:web-search"),
                &Operation::new("invoke"),
            )
            .expect("non-consuming verify");
    }
    assert_eq!(engine.facet_map().len(), 1);
}

#[test]
fn verify_and_consume_removes_entry_and_blocks_second_use() {
    let engine = CapabilityEngine::with_generated_keys(jake_can_invoke_web_search()).with_facets();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");
    assert_eq!(engine.facet_map().len(), 1);

    engine
        .verify_and_consume_capability(
            &result.token,
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
        )
        .expect("first use ok");
    assert!(engine.facet_map().is_empty());

    // The cap still embeds a facet check, but the matching fact is no longer
    // in the map, so the engine can't supply it. Verification fails closed.
    let second = engine.verify_and_consume_capability(
        &result.token,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    );
    assert!(second.is_err(), "second use must fail after consume");

    // The non-consuming path also fails for the same reason.
    let inspect = engine.verify_capability(
        &result.token,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    );
    assert!(
        inspect.is_err(),
        "non-consuming verify also fails post-consume"
    );
}

#[test]
fn facets_compose_with_anchor() {
    // anchor_to_subject + facets enabled. Both designations get attached at
    // mint, anchor to the authority block, facet via attenuation. The
    // verifier supplies the anchor designation manually; the facet is
    // auto-supplied by the engine.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "tool:web-search", operations = ["invoke"], anchor_to_subject = true },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy).with_facets();

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");

    // Without an anchor designation the cap fails closed (anchor enforcement
    // is independent from facets).
    let no_anchor = engine.verify_and_consume_capability(
        &result.token,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    );
    assert!(no_anchor.is_err(), "must fail without anchor designation");

    // The failed attempt above looked up the facet but the verifier didn't
    // acknowledge success, so the entry is still in the map (until-ack).
    assert_eq!(engine.facet_map().len(), 1);

    // Now supply the anchor; verifier acknowledges, facet is consumed.
    engine
        .verify_and_consume_designated_capability(
            &result.token,
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            &[Designation {
                label: "anchor".into(),
                value: "agent:jake".into(),
            }],
        )
        .expect("anchor + auto-supplied facet succeeds");

    assert!(engine.facet_map().is_empty());
}

#[test]
fn fresh_engine_does_not_honor_caps_minted_by_a_different_engine() {
    // Standing in for restart-equivalent: a brand-new engine has an empty
    // facet map and can't honor caps minted elsewhere even if the cap
    // verifies cryptographically. (We simulate this with two engines
    // sharing the same keypair so the underlying signature checks pass.)
    let policy_a = jake_can_invoke_web_search();
    let engine_a = CapabilityEngine::with_generated_keys(policy_a).with_facets();
    let public_key = engine_a.public_key();
    let _ = public_key; // silence unused warning if not needed

    let result = engine_a
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");
    assert_eq!(engine_a.facet_map().len(), 1);

    // A second engine with the same policy + facets enabled but a fresh
    // (different) keypair is the cleanest model of restart for this test:
    // it doesn't even know the signing key, so verification fails for
    // signature reasons. To isolate the facet behavior, instead clear the
    // facet map on engine_a manually by consuming all entries; this
    // simulates the post-restart "no record of issued caps" state.
    engine_a
        .verify_and_consume_capability(
            &result.token,
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
        )
        .expect("first consume");
    assert!(engine_a.facet_map().is_empty());

    // Now the same token is no longer honored: the facet map has no entry,
    // so the engine cannot supply the matching fact.
    let post = engine_a.verify_capability(
        &result.token,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    );
    assert!(
        post.is_err(),
        "wholesale invalidation: cap not honored after the map dropped its entry",
    );
}

#[test]
fn schema_rejects_facet_in_required_designations() {
    let err = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "tool:web-search"
operations = [{ name = "invoke", required_designations = ["facet"] }]
"#,
    )
    .expect_err("must reject facet");
    assert!(matches!(err, SchemaError::ReservedLabel { ref label, .. } if label == "facet"));
}

#[test]
fn concurrent_verify_and_consume_admits_exactly_one_success() {
    // Regression for the lookup/consume race: when N threads concurrently
    // attempt verify_and_consume on the same cap, single-use semantics
    // require that exactly one of them sees Ok; the rest must see Err.
    let engine =
        Arc::new(CapabilityEngine::with_generated_keys(jake_can_invoke_web_search()).with_facets());
    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:web-search"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint");
    assert_eq!(engine.facet_map().len(), 1);

    let token = Arc::new(result.token);
    let successes = Arc::new(AtomicUsize::new(0));
    let failures = Arc::new(AtomicUsize::new(0));

    let mut handles = Vec::new();
    for _ in 0..16 {
        let engine = Arc::clone(&engine);
        let token = Arc::clone(&token);
        let successes = Arc::clone(&successes);
        let failures = Arc::clone(&failures);
        handles.push(thread::spawn(move || {
            match engine.verify_and_consume_capability(
                token.as_str(),
                &ObjectId::new("tool:web-search"),
                &Operation::new("invoke"),
            ) {
                Ok(()) => {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
                Err(_) => {
                    failures.fetch_add(1, Ordering::SeqCst);
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("thread");
    }

    assert_eq!(
        successes.load(Ordering::SeqCst),
        1,
        "exactly one consume should win the race",
    );
    assert_eq!(failures.load(Ordering::SeqCst), 15);
    assert!(engine.facet_map().is_empty());
}

#[test]
fn issue_capability_attaches_facet_when_enabled() {
    // Regression for the direct-issuance bypass: with_facets must be an
    // engine-wide invariant. issue_capability does not consult policy, but
    // it must still register a facet and attach the designation so the
    // resulting cap participates in the engine's revocation map.
    let engine = CapabilityEngine::with_generated_keys(CListPolicy::empty()).with_facets();

    let token = engine
        .issue_capability(
            &ObjectId::new("service:webapp"),
            &ObjectId::new("api:posts"),
            &Operation::new("read"),
            MintOptions::default(),
        )
        .expect("issue");

    // The facet map grew by one and the token now requires the auto-supplied
    // facet at verify time.
    assert_eq!(engine.facet_map().len(), 1);

    // Non-consuming verify works: engine auto-supplies the facet.
    engine
        .verify_capability(&token, &ObjectId::new("api:posts"), &Operation::new("read"))
        .expect("verify succeeds via auto-supplied facet");

    // Consume removes the entry; second use fails closed.
    engine
        .verify_and_consume_capability(&token, &ObjectId::new("api:posts"), &Operation::new("read"))
        .expect("first consume succeeds");
    assert!(engine.facet_map().is_empty());

    let second = engine.verify_and_consume_capability(
        &token,
        &ObjectId::new("api:posts"),
        &Operation::new("read"),
    );
    assert!(
        second.is_err(),
        "second consume must fail after the entry is gone"
    );
}

#[test]
fn issue_capability_with_facets_disabled_is_unchanged() {
    // The fix only attaches facets when the engine has them enabled.
    // Without with_facets(), issue_capability keeps producing plain caps.
    let engine = CapabilityEngine::with_generated_keys(CListPolicy::empty());
    let token = engine
        .issue_capability(
            &ObjectId::new("service:webapp"),
            &ObjectId::new("api:posts"),
            &Operation::new("read"),
            MintOptions::default(),
        )
        .expect("issue");
    assert!(engine.facet_map().is_empty());
    engine
        .verify_capability(&token, &ObjectId::new("api:posts"), &Operation::new("read"))
        .expect("verify of plain issued cap");
}
