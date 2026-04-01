# hessra-cap

A capability security engine for Rust. Part of the [Hessra](https://hessra.net) open core.

## What is this?

`hessra-cap` implements the core of a capability security model: every operation requires a
capability token that encodes both the permission and an unforgeable reference to the object
being acted on. Verification is done locally with a public key and the facts about the current request.

A capability token is issued for one subject, one resource, one operation. The verifier
confirms the request context matches. If anything is missing or wrong, it fails closed.

## Crates

This workspace contains three crates:

| Crate | Description |
|---|---|
| `hessra-cap` | Convenience crate: re-exports the engine and default policy backend |
| `hessra-cap-engine` | Core engine: minting, verification, policy evaluation, context tokens |
| `hessra-cap-policy` | Default `CListPolicy` backend using TOML-configured capability lists |

For most use cases, depend on `hessra-cap`. For custom policy backends, depend on
`hessra-cap-engine` directly and implement the `PolicyBackend` trait.

## Quick start

```toml
[dependencies]
hessra-cap = "0.2"
```

```rust
use hessra_cap::{CapabilityEngine, CListPolicy, ObjectId, Operation, SessionConfig};

// Define policy in TOML
let policy = CListPolicy::from_toml(r#"
    [[objects]]
    id = "agent:my-agent"
    capabilities = [
        { target = "tool:web-search", operations = ["invoke"] },
    ]
"#)?;

// Create engine with generated keys
let engine = CapabilityEngine::with_generated_keys(policy);

// Mint a capability token
let result = engine.mint_capability(
    &ObjectId::new("agent:my-agent"),
    &ObjectId::new("tool:web-search"),
    &Operation::new("invoke"),
    None,
)?;

// Verify (local, no network call)
engine.verify_capability(
    &result.token,
    &ObjectId::new("tool:web-search"),
    &Operation::new("invoke"),
)?;
```

## Capability composition and designation

The engine supports cross-object delegation using `DesignationBuilder`, which lets a
service narrow a capability token for a specific user or tenant without access to the
signing key. Just the public key is needed.

```rust
use hessra_cap_token::DesignationBuilder;

// Root issues a broad capability to the webapp service
let service_token = root_engine.mint_capability(
    &ObjectId::new("service:webapp"),
    &ObjectId::new("api:users"),
    &Operation::new("read"),
    None,
)?.token;

// Webapp narrows it for a specific user at a specific tenant
// No signing key required. Attenuation only adds checks, never removes them
let user_token = DesignationBuilder::from_base64(service_token, root_public_key)?
    .designate("tenant_id".into(), "acme-corp".into())
    .designate("user".into(), "service:webapp:acme-corp:alice".into())
    .attenuate_base64()?;

// Verifier confirms both designations. This fails closed if either is missing or wrong
root_engine.verify_designated_capability(
    &user_token,
    &ObjectId::new("api:users"),
    &Operation::new("read"),
    &[
        Designation { label: "tenant_id".into(), value: "acme-corp".into() },
        Designation { label: "user".into(), value: "service:webapp:acme-corp:alice".into() },
    ],
)?;
```

The root authority never needs to know about your tenants or users. Naming lives where
the names come from.

## Information flow control

Context tokens track data exposure across a session. Once an agent reads classified data,
exposure labels accumulate in its context token and the policy engine blocks access to
tools that would violate the policy. This is done without any external service call.

```rust
// Policy with exposure rules
let policy = CListPolicy::from_toml(r#"
    [[objects]]
    id = "agent:assistant"
    capabilities = [
        { target = "tool:web-search", operations = ["invoke"] },
        { target = "tool:email", operations = ["invoke"] },
        { target = "data:user-ssn", operations = ["read"] },
    ]

    [classifications]
    "data:user-ssn" = ["PII:SSN"]

    [[exposure_rules]]
    labels = ["PII:SSN"]
    blocks = ["tool:email", "tool:web-search"]
"#)?;

let engine = CapabilityEngine::with_generated_keys(policy);
let context = engine.mint_context(&ObjectId::new("agent:assistant"), SessionConfig::default())?;

// After reading SSN data, exfiltration tools are blocked
let result = engine.mint_capability(
    &ObjectId::new("agent:assistant"),
    &ObjectId::new("data:user-ssn"),
    &Operation::new("read"),
    Some(&context),
)?;
let context = result.context.unwrap(); // updated context carries the exposure

// This now fails because PII:SSN exposure blocks email
let blocked = engine.mint_capability(
    &ObjectId::new("agent:assistant"),
    &ObjectId::new("tool:email"),
    &Operation::new("invoke"),
    Some(&context),
);
assert!(blocked.is_err());
```

Sub-agents forked from an exposed parent inherit the parent's exposure. Contamination
cannot be laundered through delegation.

## Examples

Two runnable examples cover the primary use cases:

```bash
# Webapp auth: cross-engine delegation, designation, identity tokens
cargo run --example webapp_auth -p hessra-cap

# Agent harness: information flow control, lethal trifecta prevention, sub-agent forking
cargo run --example agent_harness -p hessra-cap
```

## Token primitives

Capability and identity tokens are built on [Biscuit](https://www.biscuitsec.org/), an
open token format with cryptographic attenuation. Attenuation blocks are append-only:
tokens can only narrow, never expand. The underlying token crates (`hessra-tokens`) are
published separately and can be used without the engine for pure verification use cases.

## Managed offering

If you want a managed root authority rather than running your own, [Hessra](https://hessra.net)
offers a hosted service with key management, token issuance, and a policy API. The open
core and the managed offering use the same token format and verification primitives.

## License

Apache-2.0
