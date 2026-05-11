//! # Hessra Capability Engine
//!
//! Core capability engine for the Hessra authorization system.
//!
//! This crate provides:
//! - Unified object model where everything is an object with a capability space
//! - `PolicyBackend` trait for pluggable policy evaluation
//! - Context tokens for information flow control (exposure tracking)
//! - `CapabilityEngine` that orchestrates minting, verification, and policy evaluation

// EngineError is a rich, structured error type. The `result_large_err` lint
// would push us to box variants for clippy's stack-size threshold; we prefer
// the structured variants and accept the slightly larger Result on engine
// paths. Mint/verify are not hot enough for the size to matter in practice.
#![allow(clippy::result_large_err)]

pub mod context;
pub mod engine;
pub mod error;
pub mod facet;
pub mod resolver;
pub mod types;

pub use context::{ContextToken, HessraContext};
pub use engine::CapabilityEngine;
pub use error::{ChainCheckFailure, EngineError};
pub use facet::FacetMap;
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
