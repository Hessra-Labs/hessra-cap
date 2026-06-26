//! The capability **mechanism** layer: role-agnostic, policy-free primitives.
//!
//! Everything here knows *how* to issue, attenuate, activate, facet, and verify
//! a Hessra capability, and how to key a single-use facet ledger -- but nothing
//! about *why* a capability should be issued. There are no tool / agent /
//! ToolSystem / authority types: those roles are **compositions** of these
//! primitives, built one layer up (the policy-driven [`crate::CapabilityEngine`]
//! is one such composition; a leaf tool or a forwarder is another).
//!
//! Keys are passed in as parameters rather than owned, because different roles
//! hold different keys (an authority signs mints; a ToolSystem signs
//! activations; a context signer writes exposure). That parameterization is what
//! keeps these functions role-agnostic.
//!
//! The lifecycle these primitives compose:
//!
//! ```text
//! mint_inert ──▶ attenuate ──▶ activate (+issue_facet, ledger.register)
//!                                  │
//!                                  ▼
//!                     ledger.consume ──▶ complete_facet ──▶ verify_at_anchor
//! ```

mod ledger;

pub use ledger::FacetLedger;

use std::time::Duration;

use hessra_cap_token::{
    CapabilityVerifier, HessraCapability, get_capability_revocation_id, latest_revocation_id,
};
use hessra_context_token::ContextVerifier;
use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};

use crate::error::EngineError;
use crate::types::Designation;

/// The reserved designation label used for single-use facets. Mirrors the entry
/// in [`hessra_cap_schema::RESERVED_LABELS`].
pub const FACET_LABEL: &str = "facet";

/// Mint an **inert** (latent), anchored intermediate capability. `minter` signs
/// it as the authority; it stays inert until a holder of `activator_pk` attests
/// an `activation` fact (see [`activate`]). Typically minted long-lived and
/// tightened to a short window at activation.
#[allow(clippy::too_many_arguments)]
pub fn mint_inert(
    minter: &KeyPair,
    subject: &str,
    resource: &str,
    operation: &str,
    anchor: &str,
    activator_pk: PublicKey,
    valid_for: Duration,
    time_config: TokenTimeConfig,
) -> Result<String, EngineError> {
    HessraCapability::new()
        .subject(subject)
        .resource(resource)
        .operation(operation)
        .anchor(anchor)
        .valid_for(valid_for)
        .with_time(time_config)
        .latent(activator_pk)
        .issue(minter)
        .map_err(EngineError::from)
}

/// Mint a non-latent **birthright** capability anchored to a verifier: a cap an
/// object is "born with", usable immediately by whoever holds it (no activation
/// gate). The advanced leaf-tool case; mostly a thin wrap of the builder.
pub fn mint_birthright(
    minter: &KeyPair,
    subject: &str,
    resource: &str,
    operation: &str,
    anchor: &str,
    valid_for: Duration,
    time_config: TokenTimeConfig,
) -> Result<String, EngineError> {
    HessraCapability::new()
        .subject(subject)
        .resource(resource)
        .operation(operation)
        .anchor(anchor)
        .valid_for(valid_for)
        .with_time(time_config)
        .issue(minter)
        .map_err(EngineError::from)
}

/// Keyless attenuation: append a first-party block narrowing the capability to
/// the given designations. `root_pk` is the key the capability is rooted at.
pub fn attenuate(
    token: &str,
    root_pk: PublicKey,
    designations: &[Designation],
) -> Result<String, EngineError> {
    let mut amendment = HessraCapability::amend(token, root_pk)?;
    for d in designations {
        amendment = amendment.designation(d.label.clone(), d.value.clone());
    }
    amendment.attenuate().map_err(EngineError::from)
}

/// Activate a latent capability: `activator` attests `activation` as of now,
/// tightens the lifetime to `valid_for`, and pins a single-use `facet_id`. The
/// returned cap is activated but **facet-incomplete** -- still unverifiable until
/// [`complete_facet`] supplies the facet fact. The facet pin is bound to this
/// activation block, so a facet from another activation cannot satisfy it.
pub fn activate(
    token: &str,
    root_pk: PublicKey,
    activator: &KeyPair,
    valid_for: Duration,
    facet_id: &str,
) -> Result<String, EngineError> {
    HessraCapability::amend(token, root_pk)?
        .activate()
        .valid_for(valid_for)
        .designation_trusting(activator.public(), FACET_LABEL, facet_id)
        .attest(activator)
        .map_err(EngineError::from)
}

/// Complete the single-use facet pin on an activated capability: `activator`
/// attests the `facet` fact, making the cap verifiable. This is the forward
/// hop's augmentation, performed only as the facet is consumed from the ledger.
pub fn complete_facet(
    activated: &str,
    root_pk: PublicKey,
    activator: &KeyPair,
    facet_id: &str,
) -> Result<String, EngineError> {
    HessraCapability::amend(activated, root_pk)?
        .with_designation(FACET_LABEL, facet_id)
        .attest(activator)
        .map_err(EngineError::from)
}

/// Verify a capability at `anchor` against the authority's public key, supplying
/// the verifier's own designations. The tool-side check: the cap verifies iff
/// its activation/facet checks are satisfied and its anchor matches this
/// verifier's identity.
pub fn verify_at_anchor(
    token: &str,
    authority_pk: PublicKey,
    resource: &str,
    operation: &str,
    anchor: &str,
    designations: &[Designation],
) -> Result<(), EngineError> {
    let mut verifier = CapabilityVerifier::new(
        token.to_string(),
        authority_pk,
        resource.to_string(),
        operation.to_string(),
    )
    .anchor(anchor);
    for d in designations {
        verifier = verifier.with_designation(d.label.clone(), d.value.clone());
    }
    verifier.verify().map_err(EngineError::from)
}

/// Ledger key for a **verifier** facet: the capability's authority-block
/// revocation id, stable across attenuation.
pub fn verifier_facet_key(token: &str, root_pk: PublicKey) -> Result<String, EngineError> {
    Ok(get_capability_revocation_id(token.to_string(), root_pk)?.to_hex())
}

/// Ledger key for an **intermediary** facet: the capability's latest-block
/// revocation id, which is the activation block on an activated cap (unique per
/// activation).
pub fn intermediary_facet_key(token: &str, root_pk: PublicKey) -> Result<String, EngineError> {
    Ok(latest_revocation_id(token, root_pk)?.to_hex())
}

// -- exposure at the mechanism boundary ---------------------------------------
//
// The precluding-check and conferring-write, surfaced policy-free so a caller
// with its own label vocabulary uses them without a `PolicyBackend`. Exposure is
// applied and checked only on handout, never on the data path; the policy-driven
// classification/exposure-rules path stays a layer up in `CapabilityEngine`.

/// Whether `context` (signed by `signer_pk`) already carries an exposure `label`
/// that should preclude a handout. Returns `true` when the label is present (a
/// precluding rule would fire) and `false` when it is absent or the context is
/// unverifiable. The precluding gate the handout step consults before issuing.
pub fn exposure_precludes(context: &str, signer_pk: PublicKey, label: &str) -> bool {
    ContextVerifier::new(context.to_string(), signer_pk)
        .excludes(label)
        .verify()
        .is_err()
}

/// Append `labels` to `context`'s exposure attributed to `source`, re-signed by
/// `signer`. The conferring-write: a monotonic append. Sole-writer discipline
/// (only one keyholder ever calls this) is the caller's to keep; the mechanism
/// only provides the append. Returns the original token unchanged if `labels` is
/// empty.
pub fn add_exposure(
    context: &str,
    signer: &KeyPair,
    labels: &[String],
    source: &str,
) -> Result<String, EngineError> {
    hessra_context_token::add_exposure(context, signer, labels, source.to_string())
        .map_err(|e| EngineError::Context(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hessra_token_core::KeyPair;

    /// (authority/minter keypair, activator/forwarder keypair)
    fn roles() -> (KeyPair, KeyPair) {
        (KeyPair::new(), KeyPair::new())
    }

    fn inert(authority: &KeyPair, activator: &KeyPair, anchor: &str) -> String {
        mint_inert(
            authority,
            "agent",
            "res:x",
            "read",
            anchor,
            activator.public(),
            Duration::from_secs(3600),
            TokenTimeConfig::default(),
        )
        .unwrap()
    }

    fn verifies(token: &str, authority: &KeyPair, anchor: &str) -> bool {
        verify_at_anchor(token, authority.public(), "res:x", "read", anchor, &[]).is_ok()
    }

    #[test]
    fn intermediary_lifecycle_mint_activate_forward_verify() {
        let (authority, activator) = roles();
        let ledger = FacetLedger::new();

        // Authority mints an inert, anchored intermediate bound to the activator.
        let inert = inert(&authority, &activator, "tool:x");
        // Inert at rest: not verifiable.
        assert!(!verifies(&inert, &authority, "tool:x"));

        // Activate: tighten + pin a fresh facet, registered under the activation key.
        let facet = ledger.issue_facet();
        let activated = activate(
            &inert,
            authority.public(),
            &activator,
            Duration::from_secs(300),
            &facet,
        )
        .unwrap();
        let key = intermediary_facet_key(&activated, authority.public()).unwrap();
        ledger.register_intermediary(&key, &facet);
        // Activated but facet-incomplete: still not verifiable.
        assert!(!verifies(&activated, &authority, "tool:x"));

        // Forward: claim the facet and complete it -> now verifiable.
        let claimed = ledger.consume_intermediary(&key).expect("live facet");
        assert_eq!(claimed, facet);
        let completed =
            complete_facet(&activated, authority.public(), &activator, &claimed).unwrap();
        assert!(verifies(&completed, &authority, "tool:x"));

        // Replay: the facet is spent, so the forward path short-circuits.
        assert!(ledger.consume_intermediary(&key).is_none());
    }

    #[test]
    fn facet_bound_to_its_activation() {
        // A facet id cannot complete an activation it was not pinned to.
        let (authority, activator) = roles();
        let inert = inert(&authority, &activator, "tool:x");
        let activated = activate(
            &inert,
            authority.public(),
            &activator,
            Duration::from_secs(300),
            "facet-A",
        )
        .unwrap();

        let wrong = complete_facet(&activated, authority.public(), &activator, "facet-B").unwrap();
        assert!(!verifies(&wrong, &authority, "tool:x"));
        let right = complete_facet(&activated, authority.public(), &activator, "facet-A").unwrap();
        assert!(verifies(&right, &authority, "tool:x"));
    }

    #[test]
    fn activation_from_wrong_key_rejected() {
        // A rogue activator cannot stand in for the bound activation key.
        let (authority, activator) = roles();
        let rogue = KeyPair::new();
        let inert = inert(&authority, &activator, "tool:x");
        let activated = activate(
            &inert,
            authority.public(),
            &rogue,
            Duration::from_secs(300),
            "facet-A",
        )
        .unwrap();
        let completed = complete_facet(&activated, authority.public(), &rogue, "facet-A").unwrap();
        assert!(!verifies(&completed, &authority, "tool:x"));
    }

    #[test]
    fn birthright_mint_and_verify_at_anchor() {
        let authority = KeyPair::new();
        let cap = mint_birthright(
            &authority,
            "tool",
            "res:x",
            "read",
            "tool:x",
            Duration::from_secs(300),
            TokenTimeConfig::default(),
        )
        .unwrap();
        // Usable immediately at its anchor; no activation needed.
        assert!(verifies(&cap, &authority, "tool:x"));
        // Wrong anchor rejected.
        assert!(!verifies(&cap, &authority, "tool:y"));
    }

    #[test]
    fn exposure_confer_then_preclude() {
        use hessra_context_token::HessraContext;

        let signer = KeyPair::new();
        let ctx = HessraContext::new("agent".to_string(), TokenTimeConfig::default())
            .issue(&signer)
            .unwrap();

        // Clean context: nothing precluded.
        assert!(!exposure_precludes(&ctx, signer.public(), "tainted"));

        // Confer the label; now it precludes, but other labels stay clear.
        let ctx = add_exposure(&ctx, &signer, &["tainted".to_string()], "tool:taint").unwrap();
        assert!(exposure_precludes(&ctx, signer.public(), "tainted"));
        assert!(!exposure_precludes(&ctx, signer.public(), "other"));
    }

    #[test]
    fn add_exposure_empty_is_noop() {
        use hessra_context_token::HessraContext;

        let signer = KeyPair::new();
        let ctx = HessraContext::new("agent".to_string(), TokenTimeConfig::default())
            .issue(&signer)
            .unwrap();
        let same = add_exposure(&ctx, &signer, &[], "tool:none").unwrap();
        assert_eq!(ctx, same);
    }

    #[test]
    fn attenuate_narrows_then_requires_designation() {
        let authority = KeyPair::new();
        let cap = mint_birthright(
            &authority,
            "tool",
            "res:x",
            "read",
            "tool:x",
            Duration::from_secs(300),
            TokenTimeConfig::default(),
        )
        .unwrap();
        let narrowed = attenuate(
            &cap,
            authority.public(),
            &[Designation {
                label: "tenant".into(),
                value: "t-1".into(),
            }],
        )
        .unwrap();

        // The designation is now required.
        assert!(!verifies(&narrowed, &authority, "tool:x"));
        assert!(
            verify_at_anchor(
                &narrowed,
                authority.public(),
                "res:x",
                "read",
                "tool:x",
                &[Designation {
                    label: "tenant".into(),
                    value: "t-1".into(),
                }],
            )
            .is_ok()
        );
    }
}
