//! # Hessra Capability Engine
//!
//! Core capability engine for the Hessra authorization system.
//!
//! This crate provides:
//! - Unified object model where everything is an object with a capability space
//! - `PolicyBackend` trait for pluggable policy evaluation
//! - Context tokens for information flow control (taint tracking)
//! - `CapabilityEngine` that orchestrates minting, verification, and policy evaluation

pub mod context;
pub mod engine;
pub mod error;
pub mod types;

pub use context::{ContextToken, HessraContext};
pub use engine::CapabilityEngine;
pub use error::EngineError;
pub use types::{
    CapabilityGrant, Designation, IdentityConfig, MintOptions, MintResult, ObjectId, Operation,
    PolicyBackend, PolicyDecision, SessionConfig, TaintLabel,
};

// Re-export commonly needed types from token crates
pub use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};
