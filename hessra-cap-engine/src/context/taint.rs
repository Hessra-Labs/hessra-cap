//! Taint tracking operations for context tokens.
//!
//! Taint labels are added as append-only Biscuit blocks. Each block contains
//! `taint({label})` facts. Labels accumulate and cannot be removed.

extern crate biscuit_auth as biscuit;

use biscuit::Biscuit;
use biscuit::macros::block;
use chrono::Utc;
use hessra_token_core::{KeyPair, PublicKey};

use crate::error::EngineError;
use crate::types::{ObjectId, SessionConfig, TaintLabel};

use super::ContextToken;

/// Add taint labels to a context token.
///
/// Creates a new Biscuit block containing `taint({label})` facts for each
/// provided label, and `taint_source({source})` identifying where the taint
/// came from.
///
/// This operation is append-only: the resulting token has strictly more taint
/// than the input token.
pub fn add_taint_block(
    context: &ContextToken,
    labels: &[TaintLabel],
    source: &ObjectId,
    keypair: &KeyPair,
) -> Result<ContextToken, EngineError> {
    if labels.is_empty() {
        return Ok(context.clone());
    }

    let public_key = keypair.public();
    let biscuit = Biscuit::from_base64(context.token(), public_key)
        .map_err(|e| EngineError::Context(format!("failed to parse context token: {e}")))?;

    let source_str = source.as_str().to_string();
    let now = Utc::now().timestamp();

    // Build a block with taint facts
    let mut block_builder = block!(
        r#"
            taint_source({source_str});
            taint_time({now});
        "#
    );

    for label in labels {
        let label_str = label.as_str().to_string();
        block_builder = block_builder
            .fact(biscuit::macros::fact!(r#"taint({label_str});"#))
            .map_err(|e| EngineError::Context(format!("failed to add taint fact: {e}")))?;
    }

    let new_biscuit = biscuit
        .append(block_builder)
        .map_err(|e| EngineError::Context(format!("failed to append taint block: {e}")))?;

    let new_token = new_biscuit
        .to_base64()
        .map_err(|e| EngineError::Context(format!("failed to encode tainted token: {e}")))?;

    // Merge labels
    let mut all_labels = context.taint_labels().to_vec();
    for label in labels {
        if !all_labels.contains(label) {
            all_labels.push(label.clone());
        }
    }

    Ok(ContextToken::new(new_token, all_labels))
}

/// Extract all taint labels from a context token by parsing its Biscuit blocks.
///
/// This re-reads the token from scratch, useful when the cached labels may be stale
/// or when receiving a token from an external source.
pub fn extract_taint_labels(
    token: &str,
    public_key: PublicKey,
) -> Result<Vec<TaintLabel>, EngineError> {
    let biscuit = Biscuit::from_base64(token, public_key)
        .map_err(|e| EngineError::Context(format!("failed to parse context token: {e}")))?;

    let mut labels = Vec::new();

    // Iterate through all blocks looking for taint facts
    let block_count = biscuit.block_count();
    for i in 0..block_count {
        let block_source = biscuit.print_block_source(i).unwrap_or_default();
        // Parse taint facts from block source: lines like `taint("PII:SSN");`
        for line in block_source.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("taint(") {
                if let Some(label_str) = rest.strip_suffix(");") {
                    // Remove quotes
                    let label = label_str.trim_matches('"');
                    let taint = TaintLabel::new(label);
                    if !labels.contains(&taint) {
                        labels.push(taint);
                    }
                }
            }
        }
    }

    Ok(labels)
}

/// Fork a context token for a sub-agent, inheriting the parent's taint.
///
/// Creates a fresh context token for the child subject, pre-populated with
/// all of the parent's taint labels. This prevents contamination laundering
/// through delegation.
pub fn fork_context(
    parent: &ContextToken,
    child_subject: &ObjectId,
    session_config: SessionConfig,
    keypair: &KeyPair,
) -> Result<ContextToken, EngineError> {
    // Create a fresh context for the child
    let child = super::HessraContext::new(child_subject.clone(), session_config).issue(keypair)?;

    // If parent has no taint, just return the fresh child context
    if parent.taint_labels().is_empty() {
        return Ok(child);
    }

    // Apply all parent taint labels to the child
    let parent_source = ObjectId::new("inherited");
    add_taint_block(&child, parent.taint_labels(), &parent_source, keypair)
}
