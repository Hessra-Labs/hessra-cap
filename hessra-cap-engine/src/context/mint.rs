//! Context token minting.

extern crate biscuit_auth as biscuit;

use biscuit::macros::biscuit;
use chrono::Utc;
use hessra_token_core::KeyPair;

use crate::error::EngineError;
use crate::types::{ObjectId, SessionConfig};

use super::ContextToken;

/// Builder for creating Hessra context tokens.
///
/// Context tokens identify a session and track data exposure (taint labels)
/// as append-only Biscuit blocks.
///
/// # Example
/// ```rust,no_run
/// use hessra_cap_engine::context::HessraContext;
/// use hessra_cap_engine::types::{ObjectId, SessionConfig};
/// use hessra_token_core::KeyPair;
///
/// let keypair = KeyPair::new();
/// let token = HessraContext::new(
///     ObjectId::new("agent:openclaw"),
///     SessionConfig::default(),
/// )
/// .issue(&keypair)
/// .expect("Failed to create context token");
/// ```
pub struct HessraContext {
    subject: ObjectId,
    session_config: SessionConfig,
}

impl HessraContext {
    /// Creates a new context token builder.
    pub fn new(subject: ObjectId, session_config: SessionConfig) -> Self {
        Self {
            subject,
            session_config,
        }
    }

    /// Issues (builds and signs) the context token.
    ///
    /// The authority block contains:
    /// - `context({subject})` - identifies the session owner
    /// - time expiration check
    pub fn issue(self, keypair: &KeyPair) -> Result<ContextToken, EngineError> {
        let now = Utc::now().timestamp();
        let expiration = now + self.session_config.ttl;
        let subject = self.subject.as_str().to_string();

        let builder = biscuit!(
            r#"
                context({subject});
                check if time($time), $time < {expiration};
            "#
        );

        let biscuit = builder
            .build(keypair)
            .map_err(|e| EngineError::Context(format!("failed to build context token: {e}")))?;

        let token = biscuit
            .to_base64()
            .map_err(|e| EngineError::Context(format!("failed to encode context token: {e}")))?;

        Ok(ContextToken::new(token, vec![]))
    }
}
