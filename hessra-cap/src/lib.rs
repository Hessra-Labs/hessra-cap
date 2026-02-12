//! # Hessra Capability Engine
//!
//! Convenience crate that re-exports the Hessra capability engine with the
//! default CList policy backend.
//!
//! For custom policy backends, depend on `hessra-cap-engine` directly.
//!
//! # Quick Start
//!
//! ```rust,no_run
//! use hessra_cap::{CapabilityEngine, CListPolicy, ObjectId, Operation, SessionConfig};
//!
//! // Load policy from TOML
//! let policy = CListPolicy::from_toml(r#"
//!     [[objects]]
//!     id = "agent:my-agent"
//!     capabilities = [
//!         { target = "tool:web-search", operations = ["invoke"] },
//!     ]
//! "#).expect("Failed to parse policy");
//!
//! // Create engine with generated keys (local mode)
//! let engine = CapabilityEngine::with_generated_keys(policy);
//!
//! // Mint a context for the agent session
//! let context = engine.mint_context(
//!     &ObjectId::new("agent:my-agent"),
//!     SessionConfig::default(),
//! ).expect("Failed to mint context");
//!
//! // Mint a capability token
//! let result = engine.mint_capability(
//!     &ObjectId::new("agent:my-agent"),
//!     &ObjectId::new("tool:web-search"),
//!     &Operation::new("invoke"),
//!     Some(&context),
//! ).expect("Failed to mint capability");
//!
//! // Verify the capability token
//! engine.verify_capability(
//!     &result.token,
//!     &ObjectId::new("tool:web-search"),
//!     &Operation::new("invoke"),
//! ).expect("Verification failed");
//! ```

// Re-export everything from the engine crate
pub use hessra_cap_engine::*;

// Re-export the default policy backend
pub use hessra_cap_policy::{CListPolicy, PolicyConfig, PolicyConfigError};
