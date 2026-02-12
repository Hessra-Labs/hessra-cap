//! # Hessra Capability Policy
//!
//! Default CList (Capability List) policy backend for the Hessra capability engine.
//!
//! Provides TOML-based configuration for defining objects, their capability spaces,
//! data classifications, and taint restriction rules.

mod config;
mod matching;
mod policy;

pub use config::{PolicyConfig, PolicyConfigError};
pub use policy::CListPolicy;
