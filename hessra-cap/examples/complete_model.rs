//! Minimal progression through the Hessra capability model.
//!
//! Run with:
//! `cargo run --example complete_model -p hessra-cap`
//!
//! The three examples build from simplest to most structured:
//! direct fully designated capabilities, designating principals, and recursive
//! parent/sub-principals with designation envelopes.

use hessra_cap::{CListPolicy, CapabilityEngine, Designation, ObjectId, Operation, SchemaRegistry};

const TARGET: &str = "service:orders";
const OPERATION: &str = "read";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    direct_fully_designated_capability()?;
    designating_principal()?;
    designating_sub_principal()?;

    println!("complete model examples passed");
    Ok(())
}

fn direct_fully_designated_capability() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"
[[objects]]
id = "service:billing"
capabilities = [
    { target = "service:orders", operations = ["read"] },
]
"#,
        r#"
[[targets]]
id = "service:orders"
operations = [
    { name = "read", required_designations = ["tenant_id", "order_id"] },
]
"#,
    )?;

    let designations = [
        designation("tenant_id", "acme"),
        designation("order_id", "ord_123"),
    ];
    let token = engine
        .mint_designated_capability(
            &object("service:billing"),
            &object(TARGET),
            &operation(),
            &designations,
            None,
        )?
        .token;

    engine.verify_designated_capability(&token, &object(TARGET), &operation(), &designations)?;

    let missing_order = [designation("tenant_id", "acme")];
    assert!(
        engine
            .verify_designated_capability(&token, &object(TARGET), &operation(), &missing_order)
            .is_err()
    );

    Ok(())
}

fn designating_principal() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"
[[objects]]
id = "principal:acme"
capabilities = [
    { target = "service:orders", operations = ["read"], designations = [{ label = "tenant_id", value = "acme" }] },
]
"#,
        r#"
[[targets]]
id = "service:orders"
operations = [
    { name = "read", required_designations = ["tenant_id", "order_id"] },
]
"#,
    )?;

    let order = [designation("order_id", "ord_123")];
    let token = engine
        .mint_designated_capability(
            &object("principal:acme"),
            &object(TARGET),
            &operation(),
            &order,
            None,
        )?
        .token;

    let full_designations = [
        designation("tenant_id", "acme"),
        designation("order_id", "ord_123"),
    ];
    engine.verify_designated_capability(
        &token,
        &object(TARGET),
        &operation(),
        &full_designations,
    )?;

    let wrong_tenant = [
        designation("tenant_id", "other"),
        designation("order_id", "ord_123"),
    ];
    assert!(
        engine
            .verify_designated_capability(&token, &object(TARGET), &operation(), &wrong_tenant)
            .is_err()
    );

    Ok(())
}

fn designating_sub_principal() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"
[[objects]]
id = "principal:acme"
capabilities = [
    { target = "service:orders", operations = ["read"], designations = [{ label = "tenant_id", value = "acme" }] },
]

[[objects]]
id = "principal:acme:checkout"
parent = "principal:acme"
capabilities = [
    { target = "service:orders", operations = ["read"], designations = [
        { label = "tenant_id", value = "acme" },
        { label = "workload_id", value = "checkout" },
    ] },
]
"#,
        r#"
[[targets]]
id = "service:orders"
operations = [
    { name = "read", required_designations = ["tenant_id", "workload_id", "order_id"] },
]
"#,
    )?;

    let order = [designation("order_id", "ord_123")];
    let token = engine
        .mint_designated_capability(
            &object("principal:acme:checkout"),
            &object(TARGET),
            &operation(),
            &order,
            None,
        )?
        .token;

    let full_designations = [
        designation("tenant_id", "acme"),
        designation("workload_id", "checkout"),
        designation("order_id", "ord_123"),
    ];
    engine.verify_designated_capability(
        &token,
        &object(TARGET),
        &operation(),
        &full_designations,
    )?;

    child_cannot_exceed_parent_envelope()?;

    Ok(())
}

fn child_cannot_exceed_parent_envelope() -> Result<(), Box<dyn std::error::Error>> {
    let engine = engine(
        r#"
[[objects]]
id = "principal:acme"
capabilities = [
    { target = "service:orders", operations = ["read"], designations = [{ label = "tenant_id", value = "acme" }] },
]

[[objects]]
id = "principal:acme:checkout"
parent = "principal:acme"
capabilities = [
    { target = "service:orders", operations = ["read"], designations = [
        { label = "tenant_id", value = "other" },
        { label = "workload_id", value = "checkout" },
    ] },
]
"#,
        r#"
[[targets]]
id = "service:orders"
operations = [
    { name = "read", required_designations = ["tenant_id", "workload_id", "order_id"] },
]
"#,
    )?;

    assert!(
        engine
            .mint_designated_capability(
                &object("principal:acme:checkout"),
                &object(TARGET),
                &operation(),
                &[designation("order_id", "ord_123")],
                None,
            )
            .is_err()
    );

    Ok(())
}

fn engine(
    policy_toml: &str,
    schema_toml: &str,
) -> Result<CapabilityEngine<CListPolicy>, Box<dyn std::error::Error>> {
    let policy = CListPolicy::from_toml(policy_toml)?;
    let schema = SchemaRegistry::from_toml(schema_toml)?;
    Ok(CapabilityEngine::with_generated_keys(policy).with_schema(schema)?)
}

fn object(id: &str) -> ObjectId {
    ObjectId::new(id)
}

fn operation() -> Operation {
    Operation::new(OPERATION)
}

fn designation(label: &str, value: &str) -> Designation {
    Designation {
        label: label.into(),
        value: value.into(),
    }
}
