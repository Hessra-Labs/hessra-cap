//! The capability engine: orchestrates policy evaluation, token minting, and verification.

use hessra_cap_token::{CapabilityVerifier, DesignationBuilder, HessraCapability};
use hessra_identity_token::{HessraIdentity, IdentityVerifier};
use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};

use crate::context::{self, ContextToken, HessraContext};
use crate::error::EngineError;
use crate::types::{
    CapabilityGrant, Designation, IdentityConfig, MintOptions, MintResult, ObjectId, Operation,
    PolicyBackend, PolicyDecision, SessionConfig, TaintLabel,
};

/// The Hessra Capability Engine.
///
/// Evaluates policy, orchestrates token minting/verification, and manages
/// information flow control via context tokens.
///
/// The engine is generic over a `PolicyBackend` implementation, allowing
/// different policy models (CList, RBAC, ABAC, etc.) to be plugged in.
pub struct CapabilityEngine<P: PolicyBackend> {
    policy: P,
    keypair: KeyPair,
}

impl<P: PolicyBackend> CapabilityEngine<P> {
    /// Create a new engine with a policy backend and signing keypair.
    pub fn new(policy: P, keypair: KeyPair) -> Self {
        Self { policy, keypair }
    }

    /// Create a new engine that generates its own keypair.
    ///
    /// Useful for local/development use where the engine manages its own keys.
    pub fn with_generated_keys(policy: P) -> Self {
        Self {
            policy,
            keypair: KeyPair::new(),
        }
    }

    /// Get the engine's public key (for token verification).
    pub fn public_key(&self) -> PublicKey {
        self.keypair.public()
    }

    /// Get a reference to the policy backend.
    pub fn policy(&self) -> &P {
        &self.policy
    }

    // =========================================================================
    // Policy evaluation
    // =========================================================================

    /// Evaluate whether a capability request would be granted, without minting.
    ///
    /// Checks both the capability space (does the subject hold this capability?)
    /// and taint restrictions (would context contamination block this?).
    pub fn evaluate(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
    ) -> PolicyDecision {
        let taint_labels: Vec<TaintLabel> = context
            .map(|c| c.taint_labels().to_vec())
            .unwrap_or_default();

        self.policy
            .evaluate(subject, target, operation, &taint_labels)
    }

    // =========================================================================
    // Capability tokens
    // =========================================================================

    /// Mint a capability token for a subject to access a target with an operation.
    ///
    /// The engine:
    /// 1. Evaluates the policy (capability space + taint restrictions)
    /// 2. If granted, mints a capability token via `hessra-cap-token`
    /// 3. If the target has data classifications, auto-applies taint to the context
    ///
    /// Returns a `MintResult` containing the token and optionally an updated context.
    pub fn mint_capability(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
    ) -> Result<MintResult, EngineError> {
        // Step 1: Evaluate policy
        let decision = self.evaluate(subject, target, operation, context);
        match &decision {
            PolicyDecision::Granted => {}
            PolicyDecision::Denied { reason } => {
                return Err(EngineError::CapabilityDenied {
                    subject: subject.clone(),
                    target: target.clone(),
                    operation: operation.clone(),
                    reason: reason.clone(),
                });
            }
            PolicyDecision::DeniedByTaint {
                label,
                blocked_target,
            } => {
                return Err(EngineError::TaintRestriction {
                    label: label.clone(),
                    target: blocked_target.clone(),
                });
            }
        }

        // Step 2: Mint the capability token
        let time_config = TokenTimeConfig::default();
        let token = HessraCapability::new(
            subject.as_str().to_string(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
            time_config,
        )
        .issue(&self.keypair)
        .map_err(|e| EngineError::TokenOperation(format!("failed to mint capability: {e}")))?;

        // Step 3: Auto-apply taint if the target has data classifications
        let updated_context = if let Some(ctx) = context {
            let classifications = self.policy.classification(target);
            if classifications.is_empty() {
                Some(ctx.clone())
            } else {
                Some(context::add_taint_block(
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

    /// Verify a capability token for a target and operation.
    ///
    /// This is capability-first verification: no subject is required.
    /// The token IS the proof of authorization.
    pub fn verify_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
    ) -> Result<(), EngineError> {
        CapabilityVerifier::new(
            token.to_string(),
            self.keypair.public(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
        )
        .verify()
        .map_err(EngineError::Token)
    }

    /// Mint a capability token with additional restrictions.
    ///
    /// Like `mint_capability`, but supports namespace restriction and custom time config.
    /// This is useful when the caller needs to propagate namespace restrictions or
    /// control token lifetime.
    pub fn mint_capability_with_options(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        context: Option<&ContextToken>,
        options: MintOptions,
    ) -> Result<MintResult, EngineError> {
        // Step 1: Evaluate policy
        let decision = self.evaluate(subject, target, operation, context);
        match &decision {
            PolicyDecision::Granted => {}
            PolicyDecision::Denied { reason } => {
                return Err(EngineError::CapabilityDenied {
                    subject: subject.clone(),
                    target: target.clone(),
                    operation: operation.clone(),
                    reason: reason.clone(),
                });
            }
            PolicyDecision::DeniedByTaint {
                label,
                blocked_target,
            } => {
                return Err(EngineError::TaintRestriction {
                    label: label.clone(),
                    target: blocked_target.clone(),
                });
            }
        }

        // Step 2: Mint the token with options
        let time_config = options.time_config.unwrap_or_default();
        let mut builder = HessraCapability::new(
            subject.as_str().to_string(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
            time_config,
        );

        if let Some(namespace) = options.namespace {
            builder = builder.namespace_restricted(namespace);
        }

        let token = builder
            .issue(&self.keypair)
            .map_err(|e| EngineError::TokenOperation(format!("failed to mint capability: {e}")))?;

        // Step 3: Auto-apply taint if the target has data classifications
        let updated_context = if let Some(ctx) = context {
            let classifications = self.policy.classification(target);
            if classifications.is_empty() {
                Some(ctx.clone())
            } else {
                Some(context::add_taint_block(
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

    // =========================================================================
    // Direct token issuance (no policy evaluation)
    // =========================================================================

    /// Issue a capability token directly, without policy evaluation.
    ///
    /// Use this when the caller has already performed authorization checks
    /// through its own mechanisms (e.g., enterprise RBAC, custom domain logic).
    /// For the fully-managed path that includes policy evaluation, use
    /// `mint_capability` or `mint_capability_with_options` instead.
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

        if let Some(namespace) = options.namespace {
            builder = builder.namespace_restricted(namespace);
        }

        builder
            .issue(&self.keypair)
            .map_err(|e| EngineError::TokenOperation(format!("failed to issue capability: {e}")))
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

    /// Convenience: mint a capability and immediately attenuate with designations.
    pub fn mint_designated_capability(
        &self,
        subject: &ObjectId,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
        context: Option<&ContextToken>,
    ) -> Result<MintResult, EngineError> {
        let mut result = self.mint_capability(subject, target, operation, context)?;

        if !designations.is_empty() {
            result.token = self.attenuate_with_designations(&result.token, designations)?;
        }

        Ok(result)
    }

    /// Verify a capability token that includes designation checks.
    pub fn verify_designated_capability(
        &self,
        token: &str,
        target: &ObjectId,
        operation: &Operation,
        designations: &[Designation],
    ) -> Result<(), EngineError> {
        let mut verifier = CapabilityVerifier::new(
            token.to_string(),
            self.keypair.public(),
            target.as_str().to_string(),
            operation.as_str().to_string(),
        );

        for d in designations {
            verifier = verifier.with_designation(d.label.clone(), d.value.clone());
        }

        verifier.verify().map_err(EngineError::Token)
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

        let mut builder = HessraIdentity::new(subject.as_str().to_string(), time_config)
            .delegatable(config.delegatable);

        if let Some(namespace) = config.namespace {
            builder = builder.namespace_restricted(namespace);
        }

        builder
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

    /// Mint a fresh context token for a subject (new session, no taint).
    pub fn mint_context(
        &self,
        subject: &ObjectId,
        session_config: SessionConfig,
    ) -> Result<ContextToken, EngineError> {
        HessraContext::new(subject.clone(), session_config).issue(&self.keypair)
    }

    /// Add taint to a context token from a specific data source.
    ///
    /// Looks up the data source's classification in the policy and adds
    /// the corresponding taint labels to the context token.
    pub fn add_taint(
        &self,
        context: &ContextToken,
        data_source: &ObjectId,
    ) -> Result<ContextToken, EngineError> {
        let labels = self.policy.classification(data_source);
        if labels.is_empty() {
            return Ok(context.clone());
        }
        context::add_taint_block(context, &labels, data_source, &self.keypair)
    }

    /// Add a specific taint label directly to a context token.
    pub fn add_taint_label(
        &self,
        context: &ContextToken,
        label: TaintLabel,
        source: &ObjectId,
    ) -> Result<ContextToken, EngineError> {
        context::add_taint_block(context, &[label], source, &self.keypair)
    }

    /// Fork a context token for a sub-agent, inheriting the parent's taint.
    pub fn fork_context(
        &self,
        parent: &ContextToken,
        child_subject: &ObjectId,
        session_config: SessionConfig,
    ) -> Result<ContextToken, EngineError> {
        context::fork_context(parent, child_subject, session_config, &self.keypair)
    }

    /// Extract taint labels from a context token by re-parsing the Biscuit.
    pub fn extract_taint(&self, context: &ContextToken) -> Result<Vec<TaintLabel>, EngineError> {
        context::extract_taint_labels(context.token(), self.keypair.public())
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
