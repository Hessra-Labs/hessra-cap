//! Webapp auth flow with capability composition across two engines.
//!
//! This example demonstrates the hierarchical delegation pattern at the heart of
//! capability security:
//!
//! 1. A **root capability service** (the Hessra auth service) manages service-level
//!    authorization. It knows which services exist and what resources they may access.
//!
//! 2. A **webapp capability engine** manages user-level authorization within its own
//!    domain. It knows which users exist and what subset of the service's capabilities
//!    each user should receive.
//!
//! The key pattern shown here is **cross-engine delegation**: the root issues a broad
//! capability token to the webapp service, and the webapp narrows it per-user using
//! `DesignationBuilder` -- which requires only the root's public key, not its signing
//! key. This is a fundamental property of Biscuit tokens: attenuation (adding checks
//! that narrow scope) never requires the authority's private key.
//!
//! Note: in capability security, all entities are objects. In this example, the webapp
//! is an object, the users are objects, and the resources are objects. Objects can be
//! granted capabilities to other objects so the term "user" is used to refer to an object
//! attempting access and "resource" is an object that is being accessed.
//!
//! Run with: `cargo run --example webapp_auth -p hessra-cap`

use hessra_cap::{CListPolicy, CapabilityEngine, Designation, IdentityConfig, ObjectId, Operation};
use hessra_cap_token::DesignationBuilder;
use hessra_identity_token::{add_identity_attenuation_to_token, inspect_identity_token};
use hessra_token_core::TokenTimeConfig;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // Setup: two engines in different trust domains
    // =========================================================================

    // Root capability service -- knows about services and their allowed resources.
    let root_policy = CListPolicy::from_toml(
        r#"
        [[objects]]
        id = "service:webapp"
        can_delegate = true
        capabilities = [
            { target = "api:users", operations = ["read", "write"] },
            { target = "api:orders", operations = ["read"] },
            { target = "api:admin", operations = ["read", "write"] },
        ]
    "#,
    )?;
    let root_engine = CapabilityEngine::with_generated_keys(root_policy);

    // Webapp engine -- knows about users and their role-based access.
    // Note: alice can only read users and orders. bob can read+write users.
    // Neither has access to api:admin, even though the root grants that to
    // the webapp service (principle of least authority).
    let webapp_policy = CListPolicy::from_toml(
        r#"
        [[objects]]
        id = "user:alice"
        capabilities = [
            { target = "api:users", operations = ["read"] },
            { target = "api:orders", operations = ["read"] },
        ]

        [[objects]]
        id = "user:bob"
        capabilities = [
            { target = "api:users", operations = ["read", "write"] },
        ]
    "#,
    )?;
    let webapp_engine = CapabilityEngine::with_generated_keys(webapp_policy);

    println!("=== Webapp Auth: Capability Composition ===\n");

    // =========================================================================
    // Step 1: Root issues identity and service-level capability
    // =========================================================================

    println!("--- Step 1: Root issues service identity and capability ---");

    let webapp_identity = root_engine.mint_identity(
        &ObjectId::new("service:webapp"),
        IdentityConfig {
            delegatable: true,
            ..Default::default()
        },
    )?;
    root_engine.verify_identity(&webapp_identity, &ObjectId::new("service:webapp"))?;
    println!("Root issued and verified identity for service:webapp");

    let service_cap = root_engine
        .mint_capability(
            &ObjectId::new("service:webapp"),
            &ObjectId::new("api:users"),
            &Operation::new("read"),
            None,
        )?
        .token;
    root_engine.verify_capability(
        &service_cap,
        &ObjectId::new("api:users"),
        &Operation::new("read"),
    )?;
    println!("Root issued api:users:read capability to service:webapp\n");

    // =========================================================================
    // Step 2: Same-engine designations (the simple path)
    // =========================================================================

    println!("--- Step 2: Same-engine designations ---");

    // Root mints a tenant-scoped token in one step.
    let designated = root_engine.mint_designated_capability(
        &ObjectId::new("service:webapp"),
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        &[Designation {
            label: "tenant_id".into(),
            value: "acme-corp".into(),
        }],
        None,
    )?;

    // Verify with matching designation.
    root_engine.verify_designated_capability(
        &designated.token,
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        &[Designation {
            label: "tenant_id".into(),
            value: "acme-corp".into(),
        }],
    )?;
    println!("Tenant-scoped token verified for acme-corp");

    // Wrong tenant is rejected.
    let wrong_tenant = root_engine.verify_designated_capability(
        &designated.token,
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        &[Designation {
            label: "tenant_id".into(),
            value: "evil-corp".into(),
        }],
    );
    assert!(wrong_tenant.is_err());
    println!("Wrong tenant (evil-corp) correctly rejected\n");

    // =========================================================================
    // Step 3: Identity delegation (service delegates to user)
    // =========================================================================

    println!("--- Step 3: Identity delegation ---");

    // The service delegates its identity token to create a user-specific identity.
    // This uses third-party attenuation -- only the public key is needed, not
    // the signing key. The delegated token inherits the service's authority but
    // is scoped to the user.
    let root_public_key = root_engine.public_key();
    // The delegated identity must be a sub-identity of the service.
    // Biscuit delegation check: $a.starts_with("service:webapp:")
    let user_subject = "service:webapp:acme-corp:alice";

    let delegated_identity = add_identity_attenuation_to_token(
        webapp_identity.clone(),
        user_subject.to_string(),
        root_public_key,
        TokenTimeConfig::default(),
    )?;
    println!("Service delegated identity to {user_subject}");

    // Inspect the delegated identity to verify it works.
    let inspect = inspect_identity_token(delegated_identity.clone(), root_public_key)?;
    assert!(inspect.is_delegated);
    assert!(!inspect.is_expired);
    println!(
        "Delegated identity verified: delegated={}, identity={}",
        inspect.is_delegated, inspect.identity
    );

    // =========================================================================
    // Step 4: Cross-engine delegation with user designation (the key pattern)
    // =========================================================================

    println!("\n--- Step 4: Cross-engine delegation via DesignationBuilder ---");

    // Root issues a broad capability for the webapp service.
    let broad_token = root_engine
        .mint_capability(
            &ObjectId::new("service:webapp"),
            &ObjectId::new("api:users"),
            &Operation::new("read"),
            None,
        )?
        .token;

    // The webapp receives the broad token and narrows it for a specific user.
    // DesignationBuilder only needs the root's PUBLIC key (no signing key).
    // Biscuit attenuation blocks are unsigned -- they add checks that restrict
    // scope but can never expand it.
    //
    // Both tenant and user designations are required -- this binds the capability
    // to a specific user at a specific tenant. The user identity comes from the
    // verified delegated identity token.
    let user_token = DesignationBuilder::from_base64(broad_token, root_public_key)?
        .designate("tenant_id".into(), "acme-corp".into())
        .designate("user".into(), user_subject.into())
        .attenuate_base64()?;
    println!("Webapp narrowed root token for {user_subject} at tenant acme-corp");

    // The API layer verifies using both designations.
    // The tenant_ulid and user_subject come from the verified identity token,
    // NOT from the capability token itself.
    let user_designations = vec![
        Designation {
            label: "tenant_id".into(),
            value: "acme-corp".into(),
        },
        Designation {
            label: "user".into(),
            value: user_subject.into(),
        },
    ];
    root_engine.verify_designated_capability(
        &user_token,
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        &user_designations,
    )?;
    println!("API verified: alice can read api:users (correct tenant + user)");

    // A different user cannot reuse alice's token.
    let wrong_user = root_engine.verify_designated_capability(
        &user_token,
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        &[
            Designation {
                label: "tenant_id".into(),
                value: "acme-corp".into(),
            },
            Designation {
                label: "user".into(),
                value: "service:webapp:acme-corp:mallory".into(),
            },
        ],
    );
    assert!(wrong_user.is_err());
    println!("Token bound to alice -- rejected for mallory\n");

    // =========================================================================
    // Step 5: Webapp-level authorization (defense in depth)
    // =========================================================================

    println!("--- Step 5: Webapp-level authorization (defense in depth) ---");

    // The webapp's own policy provides an independent authorization layer.
    // Even though the root grants service:webapp write access to api:users,
    // the webapp's policy only grants alice read access.

    let alice_read = webapp_engine.evaluate(
        &ObjectId::new("user:alice"),
        &ObjectId::new("api:users"),
        &Operation::new("read"),
        None,
    );
    assert!(alice_read.is_granted());
    println!("Webapp policy: alice CAN read api:users");

    let alice_write = webapp_engine.evaluate(
        &ObjectId::new("user:alice"),
        &ObjectId::new("api:users"),
        &Operation::new("write"),
        None,
    );
    assert!(!alice_write.is_granted());
    println!("Webapp policy: alice CANNOT write api:users (restricted by webapp policy)");

    // Bob has different permissions.
    let bob_write = webapp_engine.evaluate(
        &ObjectId::new("user:bob"),
        &ObjectId::new("api:users"),
        &Operation::new("write"),
        None,
    );
    assert!(bob_write.is_granted());
    println!("Webapp policy: bob CAN write api:users");

    let bob_orders = webapp_engine.evaluate(
        &ObjectId::new("user:bob"),
        &ObjectId::new("api:orders"),
        &Operation::new("read"),
        None,
    );
    assert!(!bob_orders.is_granted());
    println!("Webapp policy: bob CANNOT read api:orders (not in bob's grants)\n");

    // =========================================================================
    // Summary
    // =========================================================================

    println!("--- Summary ---");
    println!("Root engine:  broad service-level capabilities (api:users, api:orders, api:admin)");
    println!("Webapp engine: user-level policy as defense in depth");
    println!(
        "Cross-engine: DesignationBuilder narrows root tokens per-user (no signing key needed)"
    );
    println!("Guarantee:    capabilities only narrow, never expand");

    Ok(())
}
