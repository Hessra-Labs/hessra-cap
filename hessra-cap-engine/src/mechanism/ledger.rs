//! Unified single-use facet ledger for the capability mechanism.
//!
//! One ledger serves both facet roles in the model; they differ only in *who
//! consumes and when*:
//!
//! - **verifier facet**: registered at mint, keyed by the cap's authority-block
//!   revocation id (stable across attenuation), then supplied-and-consumed at
//!   verify by the end verifier, which owns both ends.
//! - **intermediary facet**: registered at *activate*, keyed by the activation-
//!   block revocation id (the latest block at activation time), then consumed at
//!   *forward* by a non-verifier forwarder that withholds completion to force a
//!   return trip through itself.
//!
//! For an *unamended* capability the authority-block id and the latest-block id
//! are equal, so the two conventions are stored in disjoint namespaces: a
//! verifier entry and an intermediary entry can never collide on the same key.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use crate::error::EngineError;

/// Which facet convention a ledger entry belongs to. Part of the map key, so two
/// conventions that happen to share a revocation id stay separate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Convention {
    Verifier,
    Intermediary,
}

/// Per-mechanism map from a (convention, revocation-id) key to the facet id
/// pinned for that capability state.
///
/// Cloning a [`FacetLedger`] shares the underlying storage, so a clone handed to
/// a worker pool or a verify path sees the same state as the handle that
/// registered the facet. Internally synchronized with a [`Mutex`].
#[derive(Clone, Default)]
pub struct FacetLedger {
    inner: Arc<Mutex<HashMap<(Convention, String), String>>>,
}

impl FacetLedger {
    /// Build an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Mint a fresh, unique facet id. Callers shouldn't depend on the format.
    pub fn issue_facet(&self) -> String {
        uuid::Uuid::new_v4().to_string()
    }

    // --- verifier facet: register at mint, verify-and-consume at verify -------

    /// Record a verifier facet for a freshly minted capability, keyed by its
    /// authority-block revocation id.
    pub fn register_verifier(&self, key: impl Into<String>, facet: impl Into<String>) {
        self.insert(Convention::Verifier, key.into(), facet.into());
    }

    /// Non-consuming lookup of a verifier facet (the non-acknowledging verify
    /// path that supplies the fact without spending it).
    pub fn lookup_verifier(&self, key: &str) -> Option<String> {
        self.get(Convention::Verifier, key)
    }

    /// Run `verify` under the ledger lock, supplying the registered verifier
    /// facet (if any), then atomically remove the entry iff `verify` returned
    /// `Ok` and an entry was present. Lookup + verify + consume is one critical
    /// section, which is what makes single-use safe under concurrent verifiers.
    /// An `Err` leaves the entry in place so a corrected retry can succeed.
    pub fn verify_and_consume_verifier<F>(&self, key: &str, verify: F) -> Result<(), EngineError>
    where
        F: FnOnce(Option<&str>) -> Result<(), EngineError>,
    {
        self.with_entry_atomic(Convention::Verifier, key, verify, true)
    }

    // --- intermediary facet: register at activate, consume at forward ---------

    /// Record an intermediary facet for a freshly activated capability, keyed by
    /// its activation-block revocation id.
    pub fn register_intermediary(&self, key: impl Into<String>, facet: impl Into<String>) {
        self.insert(Convention::Intermediary, key.into(), facet.into());
    }

    /// Atomically remove and return the intermediary facet for `key`, if live.
    /// The removal *is* the single-use event: a second consume finds nothing and
    /// returns `None`. Done in a single critical section so two concurrent
    /// forwards cannot both claim it.
    pub fn consume_intermediary(&self, key: &str) -> Option<String> {
        self.with_entry_atomic(
            Convention::Intermediary,
            key,
            |facet| Ok::<_, EngineError>(facet.map(str::to_owned)),
            true,
        )
        .expect("consume_intermediary closure is infallible")
    }

    // --- shared atomic primitive ----------------------------------------------

    /// Look up `(convention, key)`, run `f` with the facet value (if present),
    /// and atomically remove the entry iff `consume_on_ok`, `f` returned `Ok`,
    /// and an entry was present -- all under one lock. Both consume sites express
    /// themselves through this single critical section; never split lookup and
    /// remove into two locks (that reintroduces the race this prevents).
    fn with_entry_atomic<R, F>(
        &self,
        convention: Convention,
        key: &str,
        f: F,
        consume_on_ok: bool,
    ) -> Result<R, EngineError>
    where
        F: FnOnce(Option<&str>) -> Result<R, EngineError>,
    {
        let mut guard = self.inner.lock().expect("FacetLedger mutex poisoned");
        let map_key = (convention, key.to_string());
        let facet = guard.get(&map_key).cloned();
        let result = f(facet.as_deref());
        if consume_on_ok && result.is_ok() && facet.is_some() {
            guard.remove(&map_key);
        }
        result
    }

    fn insert(&self, convention: Convention, key: String, facet: String) {
        let mut guard = self.inner.lock().expect("FacetLedger mutex poisoned");
        guard.insert((convention, key), facet);
    }

    fn get(&self, convention: Convention, key: &str) -> Option<String> {
        let guard = self.inner.lock().expect("FacetLedger mutex poisoned");
        guard.get(&(convention, key.to_string())).cloned()
    }

    /// Number of live entries across both conventions. For diagnostics and tests.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("FacetLedger mutex poisoned").len()
    }

    /// Whether the ledger holds no live facets.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for FacetLedger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FacetLedger")
            .field("entries", &self.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_and_intermediary_keys_do_not_alias() {
        // The unamended-cap hazard: the same revocation id in both conventions
        // must coexist and consume independently.
        let ledger = FacetLedger::new();
        ledger.register_verifier("rev", "v-facet");
        ledger.register_intermediary("rev", "i-facet");

        assert_eq!(ledger.lookup_verifier("rev").as_deref(), Some("v-facet"));
        assert_eq!(
            ledger.consume_intermediary("rev").as_deref(),
            Some("i-facet")
        );
        // Consuming the intermediary left the verifier entry untouched.
        assert_eq!(ledger.lookup_verifier("rev").as_deref(), Some("v-facet"));
    }

    #[test]
    fn consume_intermediary_is_single_use() {
        let ledger = FacetLedger::new();
        ledger.register_intermediary("k", "f");
        assert_eq!(ledger.consume_intermediary("k").as_deref(), Some("f"));
        assert!(ledger.consume_intermediary("k").is_none());
    }

    #[test]
    fn consume_intermediary_absent_is_none() {
        let ledger = FacetLedger::new();
        assert!(ledger.consume_intermediary("missing").is_none());
    }

    #[test]
    fn verifier_consume_removes_on_ok_keeps_on_err() {
        let ledger = FacetLedger::new();
        ledger.register_verifier("k", "f");

        // Err leaves the entry for a corrected retry.
        let r = ledger
            .verify_and_consume_verifier("k", |_| Err(EngineError::TokenOperation("x".into())));
        assert!(r.is_err());
        assert_eq!(ledger.lookup_verifier("k").as_deref(), Some("f"));

        // Ok consumes, and the closure sees the registered facet.
        let r = ledger.verify_and_consume_verifier("k", |facet| {
            assert_eq!(facet, Some("f"));
            Ok(())
        });
        assert!(r.is_ok());
        assert!(ledger.lookup_verifier("k").is_none());
    }

    #[test]
    fn verifier_consume_absent_hands_none_to_closure() {
        let ledger = FacetLedger::new();
        let r = ledger.verify_and_consume_verifier("missing", |facet| {
            assert!(facet.is_none());
            Ok(())
        });
        assert!(r.is_ok());
    }

    #[test]
    fn issue_facet_is_unique() {
        let ledger = FacetLedger::new();
        assert_ne!(ledger.issue_facet(), ledger.issue_facet());
    }

    #[test]
    fn clone_shares_storage() {
        let a = FacetLedger::new();
        let b = a.clone();
        a.register_intermediary("k", "f");
        // Consume through the clone is visible to the original.
        assert_eq!(b.consume_intermediary("k").as_deref(), Some("f"));
        assert!(a.consume_intermediary("k").is_none());
    }
}
