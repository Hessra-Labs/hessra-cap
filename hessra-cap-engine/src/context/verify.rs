//! Context token verification.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::authorizer;
use chrono::Utc;
use hessra_token_core::PublicKey;

use crate::error::EngineError;

/// Verifier for context tokens.
///
/// Checks that the context token is valid (not expired, properly signed).
pub struct ContextVerifier {
    token: String,
    public_key: PublicKey,
}

impl ContextVerifier {
    /// Creates a new context verifier.
    pub fn new(token: String, public_key: PublicKey) -> Self {
        Self { token, public_key }
    }

    /// Verify the context token.
    pub fn verify(self) -> Result<(), EngineError> {
        let biscuit = Biscuit::from_base64(&self.token, self.public_key)
            .map_err(|e| EngineError::Context(format!("invalid context token: {e}")))?;

        let now = Utc::now().timestamp();

        let authz = authorizer!(
            r#"
                time({now});
                allow if true;
            "#
        );

        authz
            .build(&biscuit)
            .map_err(|e| EngineError::Context(format!("failed to build authorizer: {e}")))?
            .authorize()
            .map_err(|e| EngineError::Context(format!("context token verification failed: {e}")))?;

        Ok(())
    }
}
