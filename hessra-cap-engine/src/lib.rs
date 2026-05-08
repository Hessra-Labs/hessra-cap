//! # Hessra Capability Engine
//!
//! Core capability engine for the Hessra authorization system.
//!
//! This crate provides:
//! - Unified object model where everything is an object with a capability space
//! - `PolicyBackend` trait for pluggable policy evaluation
//! - Context tokens for information flow control (exposure tracking)
//! - `CapabilityEngine` that orchestrates minting, verification, and policy evaluation

pub mod context;
pub mod engine;
pub mod error;
pub mod resolver;
pub mod types;

pub use context::{ContextToken, HessraContext};
pub use engine::CapabilityEngine;
pub use error::EngineError;
pub use resolver::{
    ArgsResolver, ArgsResolverBuilder, AuthSession, CompositeResolver, CompositeResolverBuilder,
    DesignationContext, DesignationResolver, Event, EventResolver, EventResolverBuilder,
    NoopResolver, RequestUrl, ResolverError, WebappResolver, WebappResolverBuilder,
};
pub use types::{
    AnchorBinding, CapabilityGrant, Designation, ExposureLabel, IdentityConfig, MintOptions,
    MintResult, ObjectId, Operation, PolicyBackend, PolicyDecision, SessionConfig,
};

// Re-export commonly needed types from token crates
pub use hessra_token_core::{KeyPair, PublicKey, TokenTimeConfig};
