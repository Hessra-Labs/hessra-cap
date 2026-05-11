//! The capability engine: orchestrates policy evaluation, token minting, and verification.

use hessra_cap_schema::{RESERVED_LABELS, SchemaRegistry};
use hessra_cap_token::{
    CapabilityVerifier, DesignationBuilder, HessraCapability, get_capability_revocation_id,
};
use hessra_identity_token::{HessraIdentity, IdentityVerifier};
use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};

use crate::context::{self, ContextToken, HessraContext};
use crate::error::EngineError;
use crate::facet::{FACET_LABEL, FacetMap, generate_facet_uuid};
use crate::resolver::{DesignationContext, DesignationResolver, NoopResolver};
use crate::types::{
    CapabilityGrant, Designation, ExposureLabel, IdentityConfig, MintOptions, MintResult, ObjectId,
    Operation, PolicyBackend, PolicyDecision, SessionConfig,
};

/// The Hessra Capability Engine.
///
/// Evaluates policy, orchestrates token minting/verification, and manages
/// information flow control via context tokens.
///
/// The engine is generic over a `PolicyBackend` implementation, allowing
/// different policy models (CList, RBAC, ABAC, etc.) to be plugged in. An
/// optional [`SchemaRegistry`] declares per-target `required_designations`
/// that the engine enforces at mint time. An optional
/// [`DesignationResolver`] supplies runtime designation values during
/// `mint_with_context`. The defaults (empty schema, [`NoopResolver`])
/// preserve the basic mint behavior for use cases that don't need either.
pub struct CapabilityEngine<P: PolicyBackend> {
    policy: P,
    schema: SchemaRegistry,
    resolver: Box<dyn DesignationResolver>,
    keypair: KeyPair,
    facets_enabled: bool,
    facet_map: FacetMap,
}

impl<P: PolicyBackend> CapabilityEngine<P> {
    /// Create a new engine with a policy backend and signing keypair.
    /// Defaults to an empty schema and a no-op resolver; chain
    /// [`Self::with_schema`] and [`Self::with_resolver`] to attach them.
    pub fn new(policy: P, keypair: KeyPair) -> Self {
        Self {
            policy,
            schema: SchemaRegistry::new(),
            resolver: Box::new(NoopResolver),
            keypair,
            facets_enabled: false,
            facet_map: FacetMap::new(),
        }
    }

    /// Create a new engine that generates its own keypair.
    ///
    /// Useful for local/development use where the engine manages its own keys.
    /// Defaults to an empty schema and a no-op resolver; chain
    /// [`Self::with_schema`] and [`Self::with_resolver`] to attach them.
    pub fn with_generated_keys(policy: P) -> Self {
        Self {
            policy,
            schema: SchemaRegistry::new(),
            resolver: Box::new(NoopResolver),
            keypair: KeyPair::new(),
            facets_enabled: false,
            facet_map: FacetMap::new(),
        }
    }

    /// Attach a schema registry to this engine. Runs cross-validation against
    /// the policy backend: every static designation declared in policy must
    /// appear in the target's schema for the matching operation.
    ///
    /// Returns the engine on success or an [`EngineError::UnknownLabelInPolicy`]
    /// (or other [`EngineError::SchemaPolicyMismatch`] variant) on the first
    /// label that does not exist in the schema.
    pub fn with_schema(mut self, schema: SchemaRegistry) -> Result<Self, EngineError> {
        cross_validate_schema_against_policy(&schema, &self.policy)?;
        self.schema = schema;
        Ok(self)
    }

    /// Attach a designation resolver to this engine. The resolver is consulted
    /// by [`Self::mint_with_context`] to supply runtime designation values for
    /// the current `(target, operation)`. Replaces any previously attached
    /// resolver.
    pub fn with_resolver<R>(mut self, resolver: R) -> Self
    where
        R: DesignationResolver + 'static,
    {
        self.resolver = Box::new(resolver);
        self
    }

    /// Enable forwarding facets on this engine. Once enabled, every minted
    /// capability gets a fresh `designation("facet", <uuid>)` attached and
    /// the engine records `(authority-block revocation id, facet uuid)` in
    /// its in-memory [`FacetMap`].
    ///
    /// The non-consuming verify path
    /// ([`Self::verify_capability`] / [`Self::verify_designated_capability`])
    /// auto-supplies the matching fact from the map when present, so existing
    /// callers continue to work unchanged. The consuming variants
    /// ([`Self::verify_and_consume_capability`] /
    /// [`Self::verify_and_consume_designated_capability`]) additionally
    /// remove the entry on a successful verification, giving single-use-on-ack
    /// semantics suitable for JIT-mint-at-dispatch.
    ///
    /// # Scope: forward-only, per-token
    ///
    /// Enabling facets affects capabilities **minted by this engine after
    /// facets are enabled**. It does not retroactively require existing
    /// non-faceted capabilities to appear in the facet map. The token itself
    /// carries its verification requirements:
    ///
    /// - A faceted capability has a `designation("facet", _)` check embedded
    ///   in its biscuit. If the engine's facet map has the entry, the engine
    ///   auto-supplies the matching fact and verification proceeds. If the
    ///   entry is absent (consumed, restart-wiped, or never registered) the
    ///   embedded check cannot be satisfied and verification fails closed.
    ///   This is the revocation, single-use, and restart-invalidation
    ///   behavior facets exist to provide.
    /// - A non-faceted capability has no facet check. Even on a
    ///   facets-enabled engine with an empty map, verification succeeds for
    ///   such a token because there is no embedded fact to satisfy. The
    ///   capability never opted into facet enforcement.
    ///
    /// In short: map miss is fine only when the token itself does not
    /// require a facet fact. This is what makes `with_facets()` safe to
    /// turn on mid-deployment — it changes future issuance, not the meaning
    /// of capabilities already in circulation.
    pub fn with_facets(mut self) -> Self {
        self.facets_enabled = true;
        self
    }

    /// A handle to the facet map. The map is shared by clone, so the returned
    /// handle observes the same state as the engine.
    pub fn facet_map(&self) -> FacetMap {
        self.facet_map.clone()
    }

    /// Whether forwarding facets are enabled on this engine.
    pub fn facets_enabled(&self) -> bool {
        self.facets_enabled
    }

    /// Get the engine's public key (for token verification).
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Get a reference to the policy backend.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    /// Get a reference to the schema registry.
    pub fn schema(&self) -> &SchemaRegistry {
        &self.schema
    }

    // =========================================================================
    // Policy evaluation
    // =========================================================================

    /// Evaluate whether a capability request would be granted, without minting.
    ///
    /// Checks both the capability space (does the subject hold this capability?)
    /// and exposure restrictions (would context exposure block this?).
    pub fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
    ) -> PolicyDecision {
        let exposure_labels: Vec<ExposureLabel> = context
            .map(|c| c.exposure_labels().to_vec())
            .unwrap_or_default();

        self.policy
            .evaluate(subject, target, operation, &exposure_labels)
    }

    // =========================================================================
    // Capability tokens
    // =========================================================================

    /// Mint a capability token for a subject to access a target with an operation.
    ///
    /// The engine:
    /// 1. Evaluates the policy (capability space + exposure restrictions)
    /// 2. If granted, mints a capability token via `hessra-cap-token`
    /// 3. If the target has data classifications, auto-applies exposure to the context
    ///
    /// Returns a `MintResult` containing the token and optionally an updated context.
    pub fn mint_capability(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
    ) -> Result<MintResult, EngineError> {
        self.mint_designated_capability(subject, target, operation, &[], context)
    }

    /// Mint a capability, asking the attached [`DesignationResolver`] to
    /// supply runtime designations from the given [`DesignationContext`].
    ///
    /// The full pipeline:
    /// 1. Evaluate policy. The matched declaration may carry static
    ///    designations and an anchor.
    /// 2. Call `resolver.resolve(target, operation, ctx)` to get runtime
    ///    designations.
    /// 3. Combine static, resolver-supplied, and an empty caller list. If the
    ///    target has a schema entry for the operation, the union must cover
    ///    every `required_designations` label (anchor and other reserved
    ///    labels excluded; they are handled separately).
    /// 4. Mint the token with the anchor (if configured) at the authority
    ///    block, then attenuate with the union of designations.
    ///
    /// Use this when the engine should drive resolution. Callers that already
    /// have designation values can keep using
    /// [`Self::mint_designated_capability`] and pre-resolve themselves.
    pub fn mint_with_context(
        &self,
        target: &ObjectId,
        operation: &Operation,
        ctx: &DesignationContext,
        context: Option<&ContextToken>,
    ) -> Result<MintResult, EngineError> {
        let resolved = self.resolver.resolve(target, operation, ctx)?;
        self.mint_inner(
            &ctx.subject,
            target,
            operation,
            &resolved,
            context,
            MintOptions::default(),
        )
    }

    /// Verify a capability token for a target and operation.
    ///
    /// This is capability-first verification: no subject is required.
    /// The token IS the proof of authorization.
    ///
    /// When forwarding facets are enabled on the engine, this method
    /// auto-supplies the matching `designation("facet", <uuid>)` fact from
    /// the facet map (if the token's authority-block revocation id is
    /// registered). This is the non-consuming path; the entry stays in the
    /// map for subsequent verifications. Use
    /// [`Self::verify_and_consume_capability`] for single-use semantics.
    pub fn verify_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
    ) -> Result<(), EngineError> {
        self.verify_designated_capability(token, target, operation, &[])
    }

    /// Verify a capability and atomically remove its facet entry from the
    /// engine's facet map on success. Single-use-on-ack: a second call sees
    /// no entry and the cap fails verification.
    ///
    /// If forwarding facets are not enabled this method behaves exactly like
    /// [`Self::verify_capability`].
    pub fn verify_and_consume_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
    ) -> Result<(), EngineError> {
        self.verify_and_consume_designated_capability(token, target, operation, &[])
    }

    /// Mint a capability token with additional restrictions.
    ///
    /// Like `mint_capability`, but supports overriding the policy's anchor
    /// binding or supplying a custom time config. When `options.anchor` is set,
    /// it takes precedence over the policy's anchor decision.
    pub fn mint_capability_with_options(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
        options: MintOptions,
    ) -> Result<MintResult, EngineError> {
        self.mint_inner(subject, target, operation, &[], context, options)
    }

    // =========================================================================
    // Direct token issuance (no policy evaluation)
    // =========================================================================

    /// Issue a capability token directly, without policy evaluation.
    ///
    /// Use this when the caller has already performed authorization checks
    /// through its own mechanisms (e.g., enterprise RBAC, custom domain logic).
    /// For the fully-managed path that includes policy evaluation, use
    /// `mint_capability` or `mint_capability_with_options` instead.
    ///
    /// Engine-wide invariants still apply: if [`Self::with_facets`] is set,
    /// the issued capability gets a fresh facet attached and registered in
    /// the engine's facet map. Policy, schema, and chain checks are
    /// deliberately bypassed (that is the point of this path); facets are an
    /// engine-level revocation mechanism rather than a policy-level check,
    /// so they continue to apply.
    pub fn issue_capability(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        options: MintOptions,
    ) -> Result<String, EngineError> {
        let time_config = options.time_config.unwrap_or_default();
        let mut builder = HessraCapability::new(
            subject.as_str().to_string(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
            time_config,
        );

        if let Some(anchor) = options.anchor {
            builder = builder.anchor_bound(anchor.as_str().to_string());
        }

        let mut token = builder
            .issue(&self.keypair)
            .map_err(|e| EngineError::TokenOperation(format!("failed to issue capability: {e}")))?;

        // Engine-level invariant: facets attach to every cap when enabled,
        // regardless of which mint path produced the cap.
        if self.facets_enabled {
            let rev_id = get_capability_revocation_id(token.clone(), self.keypair.public())
                .map_err(EngineError::Token)?
                .to_hex();
            let facet_uuid = generate_facet_uuid();
            self.facet_map.register(rev_id, facet_uuid.clone());
            token = self.attenuate_with_designations(
                &token,
                &[Designation {
                    label: FACET_LABEL.to_string(),
                    value: facet_uuid,
                }],
            )?;
        }

        Ok(token)
    }

    // =========================================================================
    // Designation attenuation
    // =========================================================================

    /// Attenuate a capability token with designations.
    ///
    /// Adds designation checks to narrow the token's scope to specific
    /// object instances. The verifier must provide matching designation facts.
    pub fn attenuate_with_designations(
        &self,
        token: &str,
        designations: &[Designation],
    ) -> Result<String, EngineError> {
        let mut builder = DesignationBuilder::from_base64(token.to_string(), self.keypair.public())
            .map_err(EngineError::Token)?;

        for d in designations {
            builder = builder.designate(d.label.clone(), d.value.clone());
        }

        builder.attenuate_base64().map_err(EngineError::Token)
    }

    /// Mint a capability with caller-supplied designations attached.
    ///
    /// The full pipeline:
    /// 1. Evaluate policy. The matched declaration may carry static
    ///    designations (author-time bindings) and an anchor.
    /// 2. Combine static designations with the caller-supplied ones.
    /// 3. If the target has a schema entry for the operation, enforce that
    ///    every `required_designations` label is present in the union.
    ///    Reserved labels (e.g., `anchor`) are excluded from this check; they
    ///    are handled through the dedicated anchor path.
    /// 4. Mint the token, attaching the anchor (if configured) at the
    ///    authority block, then attenuate with the union of designations.
    pub fn mint_designated_capability(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
        context: Option<&ContextToken>,
    ) -> Result<MintResult, EngineError> {
        self.mint_inner(
            subject,
            target,
            operation,
            designations,
            context,
            MintOptions::default(),
        )
    }

    fn mint_inner(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        caller_designations: &[Designation],
        context: Option<&ContextToken>,
        options: MintOptions,
    ) -> Result<MintResult, EngineError> {
        // Step 1: Evaluate policy.
        let decision = self.evaluate(subject, target, operation, context);
        let (policy_anchor, static_designations) = match decision {
            PolicyDecision::Granted {
                anchor,
                designations,
            } => (anchor, designations),
            PolicyDecision::Denied { reason } => {
                return Err(EngineError::CapabilityDenied {
                    subject: subject.clone(),
                    target: target.clone(),
                    operation: operation.clone(),
                    reason,
                });
            }
            PolicyDecision::DeniedByExposure {
                label,
                blocked_target,
            } => {
                return Err(EngineError::ExposureRestriction {
                    label,
                    target: blocked_target,
                });
            }
        };

        // Step 2: Compute the union of designations attached at mint.
        let mut combined: Vec<Designation> =
            Vec::with_capacity(static_designations.len() + caller_designations.len());
        combined.extend(static_designations);
        combined.extend(caller_designations.iter().cloned());

        // Step 3: Delegated identity chain check. Every ancestor of `subject`
        // must independently hold a grant for `(target, operation)` whose
        // static designations are all present in the cap being minted. This
        // encodes the model's "sub-identity capabilities bounded by parent
        // identity capabilities" property as a structural mint-time check,
        // giving transitive revocation for free: removing a grant from an
        // ancestor (or narrowing its designation envelope) invalidates
        // descendants on the next mint.
        self.walk_chain(subject, target, operation, &combined)?;

        // Step 4: Enforce required_designations from the schema, excluding
        // reserved labels (handled separately).
        if let Some(required) = self
            .schema
            .required_designations(target.as_str(), operation.as_str())
        {
            for label in required {
                if RESERVED_LABELS.contains(&label.as_str()) {
                    continue;
                }
                if !combined.iter().any(|d| d.label == *label) {
                    return Err(EngineError::MissingRequiredDesignation {
                        target: target.clone(),
                        operation: operation.clone(),
                        label: label.clone(),
                    });
                }
            }
        }

        // Step 5: Build and issue. Caller's options.anchor overrides policy's.
        let time_config = options.time_config.unwrap_or_default();
        let mut builder = HessraCapability::new(
            subject.as_str().to_string(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
            time_config,
        );
        let resolved_anchor = options.anchor.or(policy_anchor);
        if let Some(anchor) = resolved_anchor {
            builder = builder.anchor_bound(anchor.as_str().to_string());
        }
        let mut token = builder
            .issue(&self.keypair)
            .map_err(|e| EngineError::TokenOperation(format!("failed to mint capability: {e}")))?;

        // Step 6: Attach the union of designations via attenuation.
        if !combined.is_empty() {
            token = self.attenuate_with_designations(&token, &combined)?;
        }

        // Step 7: If forwarding facets are enabled, attach a fresh facet
        // designation and register it in the engine's facet map keyed by the
        // authority-block revocation id.
        if self.facets_enabled {
            let rev_id = get_capability_revocation_id(token.clone(), self.keypair.public())
                .map_err(EngineError::Token)?
                .to_hex();
            let facet_uuid = generate_facet_uuid();
            self.facet_map.register(rev_id, facet_uuid.clone());
            token = self.attenuate_with_designations(
                &token,
                &[Designation {
                    label: FACET_LABEL.to_string(),
                    value: facet_uuid,
                }],
            )?;
        }

        // Step 8: Auto-apply exposure if the target has data classifications.
        let updated_context = if let Some(ctx) = context {
            let classifications = self.policy.classification(target);
            if classifications.is_empty() {
                Some(ctx.clone())
            } else {
                Some(context::add_exposure_block(
                    ctx,
                    &classifications,
                    target,
                    &self.keypair,
                )?)
            }
        } else {
            None
        };

        Ok(MintResult {
            token,
            context: updated_context,
        })
    }

    /// Verify a capability token that includes designation checks.
    ///
    /// For anchor-bound capabilities (minted from a declaration with
    /// `anchor_to_subject` or explicit `anchor` in policy, or via
    /// `MintOptions.anchor`), the verifier MUST assert its own principal
    /// identity by including
    /// `Designation { label: "anchor", value: <its-own-principal-name> }` in
    /// `designations`. The capability verifies if and only if the anchor
    /// designation supplied here matches the anchor value embedded at mint
    /// time. In plain language, the verifier is proving "I am the principal
    /// this capability is anchored at." Anchor is treated as a regular
    /// designation at verify time; the engine does not auto-supply the
    /// verifier's identity.
    ///
    /// When forwarding facets are enabled on the engine and the token's
    /// authority-block revocation id is present in the facet map, the engine
    /// automatically supplies the matching `designation("facet", <uuid>)`
    /// fact alongside the caller-supplied designations. This is the
    /// non-consuming path; the entry stays in the map. Use
    /// [`Self::verify_and_consume_designated_capability`] for the
    /// single-use-on-ack variant.
    pub fn verify_designated_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
    ) -> Result<(), EngineError> {
        self.run_verify(token, target, operation, designations, false)?;
        Ok(())
    }

    /// Verify a designated capability and atomically remove its facet entry
    /// from the engine's facet map on success. Single-use-on-ack semantics.
    /// If forwarding facets are not enabled this is equivalent to
    /// [`Self::verify_designated_capability`].
    pub fn verify_and_consume_designated_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
    ) -> Result<(), EngineError> {
        self.run_verify(token, target, operation, designations, true)?;
        Ok(())
    }

    /// Walk the parent chain of `subject` and verify every ancestor holds a
    /// grant for `(target, operation)` whose static designations are all
    /// present in `combined`. Returns [`EngineError::ChainCheckFailed`] on
    /// the first ancestor that fails either check.
    ///
    /// This enforces "sub-identity ⊆ parent" as a structural mint-time check
    /// per the model's §4.1, covering both target/operation authority and
    /// the per-grant designation envelope: removing a grant or narrowing
    /// its designations on any ancestor invalidates all descendants on the
    /// next mint (transitive revocation, live policy). Cycle safety comes
    /// from policy load (`PolicyConfigError::ParentCycle`).
    fn walk_chain(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        combined: &[Designation],
    ) -> Result<(), EngineError> {
        let mut cursor = self.policy.parent(subject);
        while let Some(ancestor) = cursor {
            let Some(grant) = self.policy.lookup_grant(&ancestor, target, operation) else {
                return Err(EngineError::ChainCheckFailed {
                    subject: subject.clone(),
                    ancestor: ancestor.clone(),
                    target: target.clone(),
                    operation: operation.clone(),
                    reason: crate::error::ChainCheckFailure::NoGrant,
                });
            };
            // For every static designation the ancestor's grant requires,
            // the cap being minted must include a matching (label, value).
            for req in &grant.designations {
                let covered = combined
                    .iter()
                    .any(|d| d.label == req.label && d.value == req.value);
                if !covered {
                    return Err(EngineError::ChainCheckFailed {
                        subject: subject.clone(),
                        ancestor: ancestor.clone(),
                        target: target.clone(),
                        operation: operation.clone(),
                        reason: crate::error::ChainCheckFailure::DesignationNotCovered {
                            label: req.label.clone(),
                            value: req.value.clone(),
                        },
                    });
                }
            }
            cursor = self.policy.parent(&ancestor);
        }
        Ok(())
    }

    /// Internal verify driver. Auto-supplies the facet designation from the
    /// engine's facet map when facets are enabled and the cap's authority
    /// revocation id is present. When `consume` is true, lookup, verify, and
    /// removal happen under a single critical section so concurrent
    /// consumers cannot both succeed against the same facet.
    ///
    /// Absent-entry semantics (facets enabled, no map entry for the token):
    /// - If the token has a `designation("facet", _)` check embedded
    ///   (because some engine with facets enabled minted it), Biscuit
    ///   verification fails closed: the engine has no fact to supply, the
    ///   embedded check has no matching fact, the verify rejects. This is
    ///   how revocation, single-use, and restart invalidation work.
    /// - If the token has no facet check (it was minted by an engine
    ///   without facets, or by a different signer entirely), verification
    ///   proceeds normally because no fact needs to be supplied. The token
    ///   itself never opted into facet enforcement.
    ///
    /// The engine does not inspect the token's contents to decide which case
    /// applies; it lets Biscuit's logic decide based on whether the embedded
    /// checks can be satisfied.
    fn run_verify(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
        consume: bool,
    ) -> Result<(), EngineError> {
        // Build the verifier shape once: target, operation, caller designations.
        // The facet designation is auto-supplied at the call site (closure for
        // the consume path, inline read for the non-consume path).
        let build_verifier = |facet: Option<&str>| -> CapabilityVerifier {
            let mut verifier = CapabilityVerifier::new(
                token.to_string(),
                self.keypair.public(),
                target.as_str().to_string(),
                operation.as_str().to_string(),
            );
            for d in designations {
                verifier = verifier.with_designation(d.label.clone(), d.value.clone());
            }
            if let Some(facet_uuid) = facet {
                verifier =
                    verifier.with_designation(FACET_LABEL.to_string(), facet_uuid.to_string());
            }
            verifier
        };

        if !self.facets_enabled {
            // No facet wiring; build and verify without auto-supply.
            return build_verifier(None).verify().map_err(EngineError::Token);
        }

        // Facets are enabled. Extract the cap's authority-block revocation id
        // so the facet map can be consulted.
        let rev_id = get_capability_revocation_id(token.to_string(), self.keypair.public())
            .map_err(EngineError::Token)?
            .to_hex();

        if consume {
            // Consume path: lookup + verify + remove must be one critical
            // section so two callers can't both verify successfully against
            // the same entry. The closure runs under the facet map's lock;
            // on Ok return, the helper removes the entry atomically. On Err,
            // the entry is left in place to support retry with corrected
            // inputs.
            self.facet_map.verify_and_consume_atomic(&rev_id, |facet| {
                build_verifier(facet).verify().map_err(EngineError::Token)
            })
        } else {
            // Non-consume path: a stale read is harmless since nothing is
            // removed. If the entry vanishes between lookup and verify
            // (because a concurrent consume succeeded), verification will
            // fail closed and the caller can retry.
            let facet = self.facet_map.lookup(&rev_id);
            build_verifier(facet.as_deref())
                .verify()
                .map_err(EngineError::Token)
        }
    }

    // =========================================================================
    // Identity tokens
    // =========================================================================

    /// Mint an identity token for a subject.
    pub fn mint_identity(
        &self,
        subject: &ObjectId,
        config: IdentityConfig,
    ) -> Result<String, EngineError> {
        let time_config = TokenTimeConfig {
            start_time: None,
            duration: config.ttl,
        };

        HessraIdentity::new(subject.as_str().to_string(), time_config)
            .delegatable(config.delegatable)
            .issue(&self.keypair)
            .map_err(|e| EngineError::Identity(format!("failed to mint identity: {e}")))
    }

    /// Verify an identity token and return the authenticated object ID.
    ///
    /// This verifies the token as a bearer token (no specific identity required).
    pub fn authenticate(&self, token: &str) -> Result<ObjectId, EngineError> {
        // Verify the token is valid
        IdentityVerifier::new(token.to_string(), self.keypair.public())
            .verify()
            .map_err(|e| EngineError::Identity(format!("authentication failed: {e}")))?;

        // Inspect the token to extract the subject
        let inspect =
            hessra_identity_token::inspect_identity_token(token.to_string(), self.keypair.public())
                .map_err(|e| {
                    EngineError::Identity(format!("failed to inspect identity token: {e}"))
                })?;

        Ok(ObjectId::new(inspect.identity))
    }

    /// Verify an identity token for a specific identity.
    pub fn verify_identity(
        &self,
        token: &str,
        expected_identity: &ObjectId,
    ) -> Result<(), EngineError> {
        IdentityVerifier::new(token.to_string(), self.keypair.public())
            .with_identity(expected_identity.as_str().to_string())
            .verify()
            .map_err(|e| EngineError::Identity(format!("identity verification failed: {e}")))
    }

    // =========================================================================
    // Context tokens
    // =========================================================================

    /// Mint a fresh context token for a subject (new session, no exposure).
    pub fn mint_context(
        &self,
        subject: &ObjectId,
        session_config: SessionConfig,
    ) -> Result<ContextToken, EngineError> {
        HessraContext::new(subject.clone(), session_config).issue(&self.keypair)
    }

    /// Add exposure to a context token from a specific data source.
    ///
    /// Looks up the data source's classification in the policy and adds
    /// the corresponding exposure labels to the context token.
    pub fn add_exposure(
        &self,
        context: &ContextToken,
        data_source: &ObjectId,
    ) -> Result<ContextToken, EngineError> {
        let labels = self.policy.classification(data_source);
        if labels.is_empty() {
            return Ok(context.clone());
        }
        context::add_exposure_block(context, &labels, data_source, &self.keypair)
    }

    /// Add a specific exposure label directly to a context token.
    pub fn add_exposure_label(
        &self,
        context: &ContextToken,
        label: ExposureLabel,
        source: &ObjectId,
    ) -> Result<ContextToken, EngineError> {
        context::add_exposure_block(context, &[label], source, &self.keypair)
    }

    /// Fork a context token for a sub-agent, inheriting the parent's exposure.
    pub fn fork_context(
        &self,
        parent: &ContextToken,
        child_subject: &ObjectId,
        session_config: SessionConfig,
    ) -> Result<ContextToken, EngineError> {
        context::fork_context(parent, child_subject, session_config, &self.keypair)
    }

    /// Extract exposure labels from a context token by re-parsing the Biscuit.
    pub fn extract_exposure(
        &self,
        context: &ContextToken,
    ) -> Result<Vec<ExposureLabel>, EngineError> {
        context::extract_exposure_labels(context.token(), self.keypair.public())
    }

    // =========================================================================
    // Introspection
    // =========================================================================

    /// List all capability grants for a subject.
    pub fn list_grants(&self, subject: &ObjectId) -> Vec<CapabilityGrant> {
        self.policy.list_grants(subject)
    }

    /// Check if a subject can delegate capabilities.
    pub fn can_delegate(&self, subject: &ObjectId) -> bool {
        self.policy.can_delegate(subject)
    }
}

/// Walk every (subject, grant) pair the policy declares and check that any
/// static designation labels are declared in the schema for the matching
/// (target, operation). Returns the first mismatch found.
fn cross_validate_schema_against_policy<P: PolicyBackend>(
    schema: &SchemaRegistry,
    policy: &P,
) -> Result<(), EngineError> {
    if schema.is_empty() {
        // An empty schema disables enforcement; nothing to cross-validate.
        return Ok(());
    }
    for (_subject, grant) in policy.all_grants() {
        if grant.designations.is_empty() {
            continue;
        }
        for op in &grant.operations {
            let Some(required) = schema.required_designations(grant.target.as_str(), op.as_str())
            else {
                // No schema entry for this (target, op) means no enforcement
                // runs at mint time, so policy-declared static designations
                // are unconstrained too. Allow.
                continue;
            };
            for d in &grant.designations {
                if !required.iter().any(|label| label == &d.label) {
                    return Err(EngineError::UnknownLabelInPolicy {
                        target: grant.target.clone(),
                        operation: op.clone(),
                        label: d.label.clone(),
                    });
                }
            }
        }
    }
    Ok(())
}
