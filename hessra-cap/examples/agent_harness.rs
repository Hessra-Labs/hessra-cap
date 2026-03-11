//! AI agent capability harness demonstrating the lethal trifecta prevention.
//!
//! This example builds a lightweight `AgentHarness` that sits between an AI model
//! and its tools. Every tool invocation goes through the harness, which:
//!
//! 1. Evaluates policy (does the agent have this capability?)
//! 2. Checks taint restrictions (has the agent seen data that blocks this tool?)
//! 3. Mints a short-lived capability token (proof of authorization for the tool runtime)
//! 4. Updates the session context (tracks what data the agent has been exposed to)
//!
//! The "lethal trifecta" is the combination of:
//!   - Access to tools (web search, email, APIs)
//!   - Access to sensitive data (PII, financial records, credentials)
//!   - Ability to exfiltrate (send email, make web requests)
//!
//! Capability security with information flow control prevents this: once the agent
//! reads sensitive data, taint labels are added to its session context, and the
//! policy engine blocks access to exfiltration tools.
//!
//! Run with: `cargo run --example agent_harness -p hessra-cap`
//!   One design note worth highlighting: fork_context requires the parent and child
//!   to share the same engine (same keypair), because the parent's context token must be
//!   parseable by the engine doing the fork. The harness handles this by borrowing the
//!   engine (&'e CapabilityEngine) so parent and forked sub-agents naturally share the
//!   same trust domain.

use hessra_cap::{
    CListPolicy, CapabilityEngine, ContextToken, EngineError, ObjectId, Operation, SessionConfig,
    TaintLabel,
};

/// Lightweight capability harness between an AI agent and its tools.
///
/// The harness borrows a shared `CapabilityEngine` so that parent and
/// sub-agent sessions operate in the same trust domain (same signing keys,
/// same policy). Each harness instance manages its own context token, which
/// accumulates taint labels as the agent accesses classified data.
struct AgentHarness<'e> {
    engine: &'e CapabilityEngine<CListPolicy>,
    agent_id: ObjectId,
    context: ContextToken,
}

impl<'e> AgentHarness<'e> {
    /// Create a new harness for an agent session.
    fn new(
        engine: &'e CapabilityEngine<CListPolicy>,
        agent_id: ObjectId,
    ) -> Result<Self, EngineError> {
        let context = engine.mint_context(&agent_id, SessionConfig::default())?;
        Ok(Self {
            engine,
            agent_id,
            context,
        })
    }

    /// Request a capability to invoke a tool.
    ///
    /// Returns the capability token if granted. The harness automatically
    /// updates its internal context with any taint from the tool's data
    /// classification.
    fn request_tool(&mut self, tool: &ObjectId) -> Result<String, EngineError> {
        let result = self.engine.mint_capability(
            &self.agent_id,
            tool,
            &Operation::new("invoke"),
            Some(&self.context),
        )?;
        if let Some(updated) = result.context {
            self.context = updated;
        }
        Ok(result.token)
    }

    /// Request a capability to read a data source.
    ///
    /// Reading classified data adds taint labels to the session context.
    fn request_data(&mut self, data_source: &ObjectId) -> Result<String, EngineError> {
        let result = self.engine.mint_capability(
            &self.agent_id,
            data_source,
            &Operation::new("read"),
            Some(&self.context),
        )?;
        if let Some(updated) = result.context {
            self.context = updated;
        }
        Ok(result.token)
    }

    /// Check if a tool invocation would be allowed without minting a token.
    fn can_invoke(&self, tool: &ObjectId) -> bool {
        self.engine
            .evaluate(
                &self.agent_id,
                tool,
                &Operation::new("invoke"),
                Some(&self.context),
            )
            .is_granted()
    }

    /// Get the current taint labels on this session.
    fn taint_labels(&self) -> &[TaintLabel] {
        self.context.taint_labels()
    }

    /// Fork a sub-agent session that inherits this agent's taint.
    ///
    /// The sub-agent shares the same engine (same trust domain, same signing
    /// keys) but gets a forked context with all of the parent's accumulated
    /// taint. This prevents contamination laundering: a tainted agent cannot
    /// spawn a clean sub-agent to bypass restrictions.
    fn fork(&self, child_id: ObjectId) -> Result<AgentHarness<'e>, EngineError> {
        let child_context =
            self.engine
                .fork_context(&self.context, &child_id, SessionConfig::default())?;
        Ok(AgentHarness {
            engine: self.engine,
            agent_id: child_id,
            context: child_context,
        })
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // =========================================================================
    // Policy definition
    // =========================================================================
    //
    // The agent can invoke three tools (file-read, web-search, email) and
    // read three data sources (user-profile, user-ssn, public-docs).
    //
    // A sub-agent identity (agent:assistant:research-subtask) has a narrower
    // capability set -- only file-read and web-search.
    //
    // Data classifications:
    //   - user-profile is classified as PII:email + PII:address
    //   - user-ssn is classified as PII:SSN
    //   - public-docs has no classification
    //
    // Taint rules:
    //   - PII:SSN blocks tool:email and tool:web-search
    //   - PII:* (any PII) blocks tool:email

    let policy = CListPolicy::from_toml(
        r#"
        [[objects]]
        id = "agent:assistant"
        can_delegate = true
        capabilities = [
            { target = "tool:file-read", operations = ["invoke"] },
            { target = "tool:web-search", operations = ["invoke"] },
            { target = "tool:email", operations = ["invoke"] },
            { target = "data:user-profile", operations = ["read"] },
            { target = "data:user-ssn", operations = ["read"] },
            { target = "data:public-docs", operations = ["read"] },
        ]

        [[objects]]
        id = "agent:assistant:research-subtask"
        capabilities = [
            { target = "tool:file-read", operations = ["invoke"] },
            { target = "tool:web-search", operations = ["invoke"] },
        ]

        [classifications]
        "data:user-profile" = ["PII:email", "PII:address"]
        "data:user-ssn" = ["PII:SSN"]

        [[taint_rules]]
        labels = ["PII:SSN"]
        blocks = ["tool:email", "tool:web-search"]

        [[taint_rules]]
        labels = ["PII:*"]
        blocks = ["tool:email"]
    "#,
    )?;

    let engine = CapabilityEngine::with_generated_keys(policy);
    let mut harness = AgentHarness::new(&engine, ObjectId::new("agent:assistant"))?;

    println!("=== AI Agent Capability Harness ===\n");

    // =========================================================================
    // Phase 1: Clean session -- all tools available
    // =========================================================================

    println!("--- Phase 1: Clean session (no taint) ---");
    assert!(harness.taint_labels().is_empty());
    println!("Taint: (none)");
    println!(
        "tool:file-read   {}",
        status(harness.can_invoke(&ObjectId::new("tool:file-read")))
    );
    println!(
        "tool:web-search  {}",
        status(harness.can_invoke(&ObjectId::new("tool:web-search")))
    );
    println!(
        "tool:email       {}",
        status(harness.can_invoke(&ObjectId::new("tool:email")))
    );

    // Agent invokes web-search. The tool runtime would verify this token.
    let cap = harness.request_tool(&ObjectId::new("tool:web-search"))?;
    engine.verify_capability(
        &cap,
        &ObjectId::new("tool:web-search"),
        &Operation::new("invoke"),
    )?;
    println!("Invoked tool:web-search (token verified by tool runtime)\n");

    // =========================================================================
    // Phase 2: Read public docs -- no taint applied
    // =========================================================================

    println!("--- Phase 2: Read public docs (unclassified) ---");
    let _cap = harness.request_data(&ObjectId::new("data:public-docs"))?;
    println!("Read data:public-docs");
    assert!(harness.taint_labels().is_empty());
    println!("Taint: (none) -- unclassified data does not taint the session\n");

    // =========================================================================
    // Phase 3: Read user profile -- PII taint applied
    // =========================================================================

    println!("--- Phase 3: Read user profile (PII taint) ---");
    let _cap = harness.request_data(&ObjectId::new("data:user-profile"))?;
    println!("Read data:user-profile");
    println!(
        "Taint: {:?}",
        harness
            .taint_labels()
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
    );

    // PII:* blocks tool:email, but web-search is still allowed
    // (only PII:SSN blocks web-search).
    println!(
        "tool:file-read   {}",
        status(harness.can_invoke(&ObjectId::new("tool:file-read")))
    );
    println!(
        "tool:web-search  {}",
        status(harness.can_invoke(&ObjectId::new("tool:web-search")))
    );
    println!(
        "tool:email       {} (blocked by PII:* taint rule)",
        status(harness.can_invoke(&ObjectId::new("tool:email")))
    );
    println!();

    // =========================================================================
    // Phase 4: Read SSN -- the lethal trifecta is now prevented
    // =========================================================================

    println!("--- Phase 4: Read user SSN (lethal trifecta prevention) ---");
    let _cap = harness.request_data(&ObjectId::new("data:user-ssn"))?;
    println!("Read data:user-ssn");
    println!(
        "Taint: {:?}",
        harness
            .taint_labels()
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
    );

    // Now both email and web-search are blocked.
    println!(
        "tool:file-read   {}",
        status(harness.can_invoke(&ObjectId::new("tool:file-read")))
    );
    println!(
        "tool:web-search  {} (blocked by PII:SSN taint rule)",
        status(harness.can_invoke(&ObjectId::new("tool:web-search")))
    );
    println!(
        "tool:email       {} (blocked by PII:SSN + PII:* taint rules)",
        status(harness.can_invoke(&ObjectId::new("tool:email")))
    );

    // Attempting to mint the email capability gives a structured error.
    match harness.request_tool(&ObjectId::new("tool:email")) {
        Err(EngineError::TaintRestriction { label, target }) => {
            println!("Blocked: taint '{label}' prevents access to '{target}'");
        }
        other => panic!("Expected TaintRestriction, got: {other:?}"),
    }
    println!("The lethal trifecta (tools + data + exfiltration) is prevented.\n");

    // =========================================================================
    // Phase 5: Sub-agent forking with inherited taint
    // =========================================================================

    println!("--- Phase 5: Sub-agent forking ---");
    let sub_harness = harness.fork(ObjectId::new("agent:assistant:research-subtask"))?;

    println!("Forked sub-agent: {}", sub_harness.agent_id.as_str());
    println!(
        "Inherited taint: {:?}",
        sub_harness
            .taint_labels()
            .iter()
            .map(|t| t.as_str())
            .collect::<Vec<_>>()
    );

    // The sub-agent has a narrower capability set (no email at all in policy)
    // AND inherits the parent's taint. Even its allowed tools are restricted.
    println!(
        "Sub-agent tool:file-read   {}",
        status(sub_harness.can_invoke(&ObjectId::new("tool:file-read")))
    );
    println!(
        "Sub-agent tool:web-search  {} (inherited PII:SSN taint)",
        status(sub_harness.can_invoke(&ObjectId::new("tool:web-search")))
    );
    println!(
        "Sub-agent tool:email       {} (not in sub-agent's capability space)",
        status(sub_harness.can_invoke(&ObjectId::new("tool:email")))
    );
    println!("Contamination laundering through delegation: PREVENTED\n");

    // =========================================================================
    // Phase 6: Introspection
    // =========================================================================

    println!("--- Phase 6: Introspection ---");
    let grants = engine.list_grants(&ObjectId::new("agent:assistant"));
    println!("Agent capability space ({} grants):", grants.len());
    for grant in &grants {
        let ops: Vec<&str> = grant.operations.iter().map(|o| o.as_str()).collect();
        println!("  {} -> [{}]", grant.target, ops.join(", "));
    }
    println!(
        "Can delegate: {}",
        engine.can_delegate(&ObjectId::new("agent:assistant"))
    );

    println!("\n=== Example completed successfully ===");

    Ok(())
}

fn status(allowed: bool) -> &'static str {
    if allowed { "ALLOWED" } else { "BLOCKED" }
}
