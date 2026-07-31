//! Leaf tool: a non-forwarder composition built **only** from the `hessra-cap`
//! mechanism layer.
//!
//! This is the role-agnostic proof. The ToolSystem (a forwarder) composes
//! `mint_inert -> activate -> ledger -> complete_facet -> verify` from these same
//! primitives; here we build something that is *not* a forwarder at all -- a leaf
//! tool that is minted a birthright capability and verifies it at its own anchor.
//! Neither `CapabilityEngine` nor `PolicyBackend` is constructed: there is no
//! policy here, only mechanism.
//!
//! Run with: `cargo run --example leaf_tool`

use hessra_cap::mechanism::{self, FacetLedger};
use hessra_cap::{Designation, KeyPair, PublicKey, TokenTimeConfig};
use std::time::Duration;

/// A leaf tool fronting a resource. It holds only the authority's **public** key
/// -- it can verify capabilities but cannot mint, escalate, or forge them. Its
/// whole job is to verify a token it is handed, at its own anchor.
struct LeafTool {
    anchor: String,
    resource: String,
    operation: String,
    authority_pk: PublicKey,
}

impl LeafTool {
    /// Verify a capability the way a tool does on its data path: at its own
    /// anchor, against the authority key, supplying any designations it can
    /// assert about itself.
    fn verify(&self, cap: &str, designations: &[Designation]) -> bool {
        mechanism::verify_at_anchor(
            cap,
            self.authority_pk,
            &self.resource,
            &self.operation,
            &self.anchor,
            designations,
            TokenTimeConfig::default(),
        )
        .is_ok()
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The trust root. In a real deployment this lives behind a CapAuthority and
    // tools are configured with only its public key.
    let authority = KeyPair::new();

    let clock = LeafTool {
        anchor: "tool:clock".to_string(),
        resource: "clock:read".to_string(),
        operation: "invoke".to_string(),
        authority_pk: authority.public(),
    };

    println!("== Leaf tool composed from hessra-cap mechanism primitives ==\n");

    // --- 1. Birthright: minted once, usable directly (no activation gate) -----
    let cap = mechanism::mint_birthright(
        &authority,
        "tool",
        &clock.resource,
        &clock.operation,
        &clock.anchor,
        Duration::from_secs(300),
        TokenTimeConfig::default(),
    )?;
    println!(
        "1. birthright minted, tool verifies at its anchor : {}",
        verdict(clock.verify(&cap, &[]))
    );

    // --- 2. Anchor binding: a cap for this tool is useless at another ---------
    let other = LeafTool {
        anchor: "tool:weather".to_string(),
        ..clone_shape(&clock)
    };
    println!(
        "2. same cap presented at the wrong tool's anchor   : {}",
        verdict(!other.verify(&cap, &[]))
    );

    // --- 3. Attenuation: keylessly narrow the cap to a designation ------------
    let scoped = mechanism::attenuate(
        &cap,
        authority.public(),
        &[Designation {
            label: "zone".into(),
            value: "utc".into(),
        }],
    )?;
    let zone = Designation {
        label: "zone".into(),
        value: "utc".into(),
    };
    println!(
        "3. attenuated cap denied without the designation   : {}",
        verdict(!clock.verify(&scoped, &[]))
    );
    println!(
        "   ...and authorized once the designation is supplied : {}",
        verdict(clock.verify(&scoped, std::slice::from_ref(&zone)))
    );

    // --- 4. Verifier-facet single-use: the tool owns both ends ----------------
    // Unlike the forwarder's intermediary facet, here the *verifier* registers a
    // facet at mint and consumes it at verify -- no intermediary withholds it.
    // The same FacetLedger serves this convention.
    let ledger = FacetLedger::new();
    let key = mechanism::verifier_facet_key(&cap, authority.public())?;
    let facet = ledger.issue_facet();
    let single_use = mechanism::attenuate(
        &cap,
        authority.public(),
        &[Designation {
            label: mechanism::FACET_LABEL.into(),
            value: facet.clone(),
        }],
    )?;
    ledger.register_verifier(&key, &facet);

    let consume = |token: &str| {
        ledger.verify_and_consume_verifier(&key, |live| {
            let live = live.ok_or_else(|| {
                hessra_cap::EngineError::TokenOperation("facet already spent".into())
            })?;
            mechanism::verify_at_anchor(
                token,
                authority.public(),
                &clock.resource,
                &clock.operation,
                &clock.anchor,
                &[Designation {
                    label: mechanism::FACET_LABEL.into(),
                    value: live.to_string(),
                }],
                TokenTimeConfig::default(),
            )
        })
    };
    println!(
        "4. single-use cap: first verify spends the facet   : {}",
        verdict(consume(&single_use).is_ok())
    );
    println!(
        "   ...and the replay finds no live facet, denied   : {}",
        verdict(consume(&single_use).is_err())
    );

    println!("\nAll composed from mechanism primitives -- no PolicyBackend, no CapabilityEngine.");
    Ok(())
}

fn verdict(ok: bool) -> &'static str {
    if ok { "OK" } else { "FAIL" }
}

/// Copy a tool's resource/operation/authority, leaving the anchor to the caller.
fn clone_shape(t: &LeafTool) -> LeafTool {
    LeafTool {
        anchor: String::new(),
        resource: t.resource.clone(),
        operation: t.operation.clone(),
        authority_pk: t.authority_pk,
    }
}
