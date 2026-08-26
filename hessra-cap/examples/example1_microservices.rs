//! Example 1: a root authority issuing capabilities for microservice calls.
//!
//! Run with:
//! `cargo run --example example1_microservices -p hessra-cap`

use hessra_cap::{CListPolicy, CapabilityEngine, Designation, ObjectId, Operation};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    basic_microservice_post()?;
    region_designated_microservice_post()?;

    println!("example1_microservices passed");
    Ok(())
}

fn basic_microservice_post() -> Result<(), Box<dyn std::error::Error>> {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "main_application"
capabilities = [
    { target = "microservice", operations = ["post"] },
]
"#,
    )?;
    let root_authority = CapabilityEngine::with_generated_keys(policy);

    let capability = root_authority
        .mint_capability(
            &object("main_application"),
            &object("microservice"),
            &operation("post"),
            None,
        )?
        .token;

    root_authority.verify_capability(&capability, &object("microservice"), &operation("post"))?;

    Ok(())
}

fn region_designated_microservice_post() -> Result<(), Box<dyn std::error::Error>> {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "us:main_application"
capabilities = [
    { target = "microservice", operations = ["post"], designations = [{ label = "region", value = "us" }] },
]

[[objects]]
id = "eu:main_application"
capabilities = [
    { target = "microservice", operations = ["post"], designations = [{ label = "region", value = "eu" }] },
]
"#,
    )?;
    let root_authority = CapabilityEngine::with_generated_keys(policy);

    let us_capability = root_authority
        .mint_capability(
            &object("us:main_application"),
            &object("microservice"),
            &operation("post"),
            None,
        )?
        .token;
    let eu_capability = root_authority
        .mint_capability(
            &object("eu:main_application"),
            &object("microservice"),
            &operation("post"),
            None,
        )?
        .token;

    root_authority.verify_designated_capability(
        &us_capability,
        &object("microservice"),
        &operation("post"),
        &[designation("region", "us")],
    )?;
    root_authority.verify_designated_capability(
        &eu_capability,
        &object("microservice"),
        &operation("post"),
        &[designation("region", "eu")],
    )?;

    assert!(
        root_authority
            .verify_designated_capability(
                &us_capability,
                &object("microservice"),
                &operation("post"),
                &[designation("region", "eu")],
            )
            .is_err()
    );

    Ok(())
}

fn object(id: &str) -> ObjectId {
    ObjectId::new(id)
}

fn operation(name: &str) -> Operation {
    Operation::new(name)
}

fn designation(label: &str, value: &str) -> Designation {
    Designation {
        label: label.into(),
        value: value.into(),
    }
}
