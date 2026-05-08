//! Forwarding facets: per-engine in-memory revocation map for capabilities.
//!
//! When an engine is constructed with [`crate::CapabilityEngine::with_facets`],
//! every minted capability gets a fresh facet UUID attached as a structural
//! `designation("facet", <uuid>)`. The engine stores a mapping from each
//! capability's authority-block revocation id to its facet UUID. At verify
//! time, the engine consults the map to supply the matching fact, and the
//! consuming verify variants atomically remove the entry on a successful
//! verification.
//!
//! Lifecycle, paraphrasing the spec: **good until one successful use, until
//! ack, while not expired.**
//!
//! - *One successful use*: [`CapabilityEngine::verify_and_consume_capability`]
//!   removes the entry on success. A second call sees no entry and the cap
//!   fails verification (the facet check has no fact to satisfy).
//! - *Until ack*: removal happens after the verifier returns success, not at
//!   the moment of lookup. A retry that never reaches the verifier (e.g., a
//!   network blip in a distributed deployment, or a panic before
//!   acknowledgment in the in-process case) leaves the entry in the map and
//!   the next attempt succeeds.
//! - *While not expired*: the underlying token's expiry is enforced by
//!   Biscuit's time check; the facet map rides on top.
//!
//! The map is in-memory and lost on engine restart. This is intentional: a
//! restarted engine has no provenance for previously issued capabilities and
//! cannot honor them.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Built-in designation label used for forwarding facets. Mirrors the entry
/// in [`hessra_cap_schema::RESERVED_LABELS`].
pub(crate) const FACET_LABEL: &str = "facet";

/// Per-engine map from authority-block revocation id (hex) to the facet
/// UUID attached to the corresponding capability.
///
/// Cloning the [`FacetMap`] shares the same underlying storage, so handing a
/// clone to a worker pool, a verify path, or a test harness sees the same
/// state as the engine that minted the cap. The map is internally
/// synchronized with a [`Mutex`].
#[derive(Clone, Default)]
pub struct FacetMap {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl FacetMap {
    /// Build an empty facet map.
    pub fn new() -> Self {
        Self::default()
    }

    /// Register the (revocation id, facet uuid) pair for a freshly minted
    /// capability. Called by the engine at mint time.
    pub(crate) fn register(&self, revocation_id_hex: String, facet_uuid: String) {
        let mut guard = self.inner.lock().expect("FacetMap mutex poisoned");
        guard.insert(revocation_id_hex, facet_uuid);
    }

    /// Look up the facet uuid for a given revocation id. Used by the
    /// non-consuming verify path.
    pub(crate) fn lookup(&self, revocation_id_hex: &str) -> Option<String> {
        let guard = self.inner.lock().expect("FacetMap mutex poisoned");
        guard.get(revocation_id_hex).cloned()
    }

    /// Remove the entry for a revocation id. Returns the previously stored
    /// facet uuid, if any. Used by the consuming verify path after the
    /// underlying verifier acknowledged success.
    pub(crate) fn consume(&self, revocation_id_hex: &str) -> Option<String> {
        let mut guard = self.inner.lock().expect("FacetMap mutex poisoned");
        guard.remove(revocation_id_hex)
    }

    /// Number of entries currently in the map. Useful for tests and
    /// diagnostics.
    pub fn len(&self) -> usize {
        self.inner.lock().expect("FacetMap mutex poisoned").len()
    }

    /// Whether the map is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl std::fmt::Debug for FacetMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FacetMap")
            .field("entries", &self.len())
            .finish()
    }
}

/// Generate a fresh facet uuid. Currently uses UUID v4; the engine's caller
/// shouldn't depend on the format.
pub(crate) fn generate_facet_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_returns_registered_uuid() {
        let map = FacetMap::new();
        map.register("rev-a".into(), "uuid-1".into());
        assert_eq!(map.lookup("rev-a").as_deref(), Some("uuid-1"));
        assert!(map.lookup("rev-other").is_none());
    }

    #[test]
    fn consume_removes_entry() {
        let map = FacetMap::new();
        map.register("rev-a".into(), "uuid-1".into());
        assert_eq!(map.consume("rev-a").as_deref(), Some("uuid-1"));
        assert!(map.lookup("rev-a").is_none());
        assert!(map.consume("rev-a").is_none());
    }

    #[test]
    fn clone_shares_storage() {
        let a = FacetMap::new();
        let b = a.clone();
        a.register("rev-a".into(), "uuid-1".into());
        assert_eq!(b.lookup("rev-a").as_deref(), Some("uuid-1"));
        b.consume("rev-a");
        assert!(a.lookup("rev-a").is_none());
    }

    #[test]
    fn generate_uuid_is_unique() {
        let a = generate_facet_uuid();
        let b = generate_facet_uuid();
        assert_ne!(a, b);
    }
}
