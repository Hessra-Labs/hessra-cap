//! Designation resolvers turn runtime context into the designations the
//! engine attaches at mint time.
//!
//! A [`DesignationResolver`] is consulted by
//! [`crate::CapabilityEngine::mint_with_context`] after policy evaluation:
//! the engine asks the resolver for designation values for the current
//! `(target, operation)` given a [`DesignationContext`], merges the result
//! with any policy-declared static designations, and validates the union
//! against the schema's `required_designations`.
//!
//! Stock implementations:
//!
//! - [`NoopResolver`]: returns no designations. Default if no resolver is
//!   attached to the engine.
//! - [`ArgsResolver`]: declarative `(target, arg_field) -> designation_label`
//!   mappings.
//!
//! Future: `WebappResolver`, `EventResolver`, `CompositeResolver` (Sub-step 2c).

use std::any::{Any, TypeId};
use std::collections::HashMap;

use thiserror::Error;

use crate::types::{Designation, ObjectId, Operation};

/// A resolver that turns a `(target, operation, context)` triple into the
/// designations the engine will attach to the minted capability.
///
/// Implementations should be stateless or use interior mutability; the
/// engine holds the resolver as `Box<dyn DesignationResolver>` and calls it
/// concurrently from many mint paths.
pub trait DesignationResolver: Send + Sync {
    fn resolve(
        &self,
        target: &ObjectId,
        operation: &Operation,
        ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError>;
}

/// Default resolver. Returns no designations regardless of input.
///
/// Used when an engine is constructed without an explicit resolver. This
/// preserves the pre-resolver behavior: `mint_capability` and
/// `mint_designated_capability` work as before, and `mint_with_context` is
/// equivalent to passing `&[]` as caller designations.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopResolver;

impl DesignationResolver for NoopResolver {
    fn resolve(
        &self,
        _target: &ObjectId,
        _operation: &Operation,
        _ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError> {
        Ok(Vec::new())
    }
}

/// Per-call context handed to a [`DesignationResolver`].
///
/// The typed core (`subject`, `args`) covers the most common shapes; the
/// extension bag carries anything else the caller wants to make available
/// to resolvers, keyed by Rust type. A `WebappResolver`, for instance,
/// reads its session via `ctx.get::<AuthSession>()` where `AuthSession`
/// is whatever the consuming application defines.
pub struct DesignationContext {
    /// The principal that will be the subject of the minted capability.
    pub subject: ObjectId,
    /// Per-call arguments (e.g., the JSON body of a tool invocation).
    pub args: Option<serde_json::Value>,
    extensions: HashMap<TypeId, Box<dyn Any + Send + Sync>>,
}

impl DesignationContext {
    /// Build a context for a subject. Args and extensions are unset; chain
    /// [`Self::with_args`] and [`Self::insert`] as needed.
    pub fn new(subject: ObjectId) -> Self {
        Self {
            subject,
            args: None,
            extensions: HashMap::new(),
        }
    }

    /// Attach per-call arguments (consuming the context).
    pub fn with_args(mut self, args: serde_json::Value) -> Self {
        self.args = Some(args);
        self
    }

    /// Insert a typed extension. Replaces any existing value of the same type.
    pub fn insert<T: Any + Send + Sync>(&mut self, ext: T) {
        self.extensions.insert(TypeId::of::<T>(), Box::new(ext));
    }

    /// Fetch a typed extension by its concrete type.
    pub fn get<T: Any + Send + Sync>(&self) -> Option<&T> {
        self.extensions
            .get(&TypeId::of::<T>())
            .and_then(|b| b.downcast_ref::<T>())
    }
}

impl std::fmt::Debug for DesignationContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DesignationContext")
            .field("subject", &self.subject)
            .field("args", &self.args)
            .field("extensions", &format_args!("{} ext", self.extensions.len()))
            .finish()
    }
}

/// Errors a [`DesignationResolver`] can return.
#[derive(Error, Debug)]
pub enum ResolverError {
    /// The resolver could not find a value for the requested designation
    /// label, e.g., because an expected arg field was missing.
    #[error("resolver could not supply designation '{label}': {detail}")]
    MissingField { label: String, detail: String },

    /// The context was present but not in the shape the resolver needed
    /// (e.g., expected JSON object, got an array).
    #[error("resolver context has the wrong shape: {reason}")]
    InvalidShape { reason: String },

    /// Generic resolver failure for cases that don't fit the above.
    #[error("resolver failed: {0}")]
    Other(String),
}

// ---------------------------------------------------------------------------
// ArgsResolver
// ---------------------------------------------------------------------------

/// A resolver that pulls designation values from a JSON `args` object on the
/// [`DesignationContext`], mapping arg field names to designation labels
/// per target.
///
/// Use [`ArgsResolver::builder`] to start a builder; chain `.for_target(id)`
/// followed by `.map(arg_field, designation_label)` calls; call `.build()`
/// to finalize. A single resolver instance can cover any number of targets.
///
/// # Example
///
/// ```rust,no_run
/// use hessra_cap_engine::ArgsResolver;
///
/// let resolver = ArgsResolver::builder()
///     .for_target("filesystem:source")
///     .map("path", "path_prefix")
///     .for_target("tool:web-search")
///     .map("query", "query_text")
///     .build();
/// ```
#[derive(Debug, Default, Clone)]
pub struct ArgsResolver {
    per_target: HashMap<ObjectId, HashMap<String, String>>,
}

impl ArgsResolver {
    /// Begin building a new resolver.
    pub fn builder() -> ArgsResolverBuilder {
        ArgsResolverBuilder::default()
    }
}

impl DesignationResolver for ArgsResolver {
    fn resolve(
        &self,
        target: &ObjectId,
        _operation: &Operation,
        ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError> {
        let Some(mappings) = self.per_target.get(target) else {
            // No mappings declared for this target: nothing to contribute.
            return Ok(Vec::new());
        };
        if mappings.is_empty() {
            return Ok(Vec::new());
        }

        let args = ctx.args.as_ref().ok_or_else(|| ResolverError::InvalidShape {
            reason: format!(
                "ArgsResolver needs ctx.args to resolve designations for target '{target}', but args is None",
            ),
        })?;

        let obj = args
            .as_object()
            .ok_or_else(|| ResolverError::InvalidShape {
                reason: "ArgsResolver expects ctx.args to be a JSON object".to_string(),
            })?;

        let mut out = Vec::with_capacity(mappings.len());
        for (arg_field, label) in mappings {
            let value = obj
                .get(arg_field)
                .ok_or_else(|| ResolverError::MissingField {
                    label: label.clone(),
                    detail: format!("arg field '{arg_field}' not present in ctx.args"),
                })?;
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                other => {
                    return Err(ResolverError::InvalidShape {
                        reason: format!(
                            "arg '{arg_field}' for designation '{label}' must be a string, number, or bool, got {}",
                            describe_json_kind(other),
                        ),
                    });
                }
            };
            out.push(Designation {
                label: label.clone(),
                value: value_str,
            });
        }
        Ok(out)
    }
}

fn describe_json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Staged builder for [`ArgsResolver`]. Call `.for_target(id)` to scope
/// subsequent `.map()` calls to that target.
#[derive(Debug, Default)]
pub struct ArgsResolverBuilder {
    per_target: HashMap<ObjectId, HashMap<String, String>>,
    current: Option<ObjectId>,
}

impl ArgsResolverBuilder {
    /// Set the target for subsequent `.map()` calls. Re-calling with a
    /// different id switches scope; calling with the same id is a no-op.
    pub fn for_target(mut self, target: impl Into<ObjectId>) -> Self {
        let id = target.into();
        self.per_target.entry(id.clone()).or_default();
        self.current = Some(id);
        self
    }

    /// Map a JSON arg field to a designation label, scoped to the current
    /// target set by the most recent `.for_target()` call.
    ///
    /// # Panics
    ///
    /// Panics if called before `.for_target()`. The current target is
    /// programmer-set state, so a missing target is a programming error
    /// rather than a runtime condition.
    pub fn map(mut self, arg_field: impl Into<String>, label: impl Into<String>) -> Self {
        let current = self
            .current
            .as_ref()
            .expect("ArgsResolverBuilder::map called before for_target()");
        self.per_target
            .get_mut(current)
            .expect("for_target inserted an empty map")
            .insert(arg_field.into(), label.into());
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> ArgsResolver {
        ArgsResolver {
            per_target: self.per_target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx_with_args(subject: &str, args: serde_json::Value) -> DesignationContext {
        DesignationContext::new(ObjectId::new(subject)).with_args(args)
    }

    #[test]
    fn noop_resolver_returns_empty() {
        let r = NoopResolver;
        let ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        let out = r
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect("noop");
        assert!(out.is_empty());
    }

    #[test]
    fn args_resolver_maps_declared_fields() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        let ctx = ctx_with_args("agent:jake", json!({ "path": "code/hessra/" }));
        let out = resolver
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "path_prefix");
        assert_eq!(out[0].value, "code/hessra/");
    }

    #[test]
    fn args_resolver_missing_field_errors() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        let ctx = ctx_with_args("agent:jake", json!({ "other": "x" }));
        let err = resolver
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect_err("must miss");
        match err {
            ResolverError::MissingField { label, .. } => assert_eq!(label, "path_prefix"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn args_resolver_unknown_target_returns_empty() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        let ctx = ctx_with_args("agent:jake", json!({}));
        let out = resolver
            .resolve(
                &ObjectId::new("tool:other-thing"),
                &Operation::new("invoke"),
                &ctx,
            )
            .expect("unknown target");
        assert!(out.is_empty());
    }

    #[test]
    fn args_resolver_multi_target() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .for_target("tool:discord-dm")
            .map("user_id", "user_id")
            .build();

        let ctx = ctx_with_args("agent:jake", json!({ "user_id": "u-42" }));
        let out = resolver
            .resolve(
                &ObjectId::new("tool:discord-dm"),
                &Operation::new("send"),
                &ctx,
            )
            .expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "user_id");
        assert_eq!(out[0].value, "u-42");
    }

    #[test]
    fn args_resolver_rejects_non_object_args() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        let ctx = ctx_with_args("agent:jake", json!(["not", "an", "object"]));
        let err = resolver
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect_err("must reject non-object");
        assert!(matches!(err, ResolverError::InvalidShape { .. }));
    }

    #[test]
    fn args_resolver_rejects_missing_args() {
        let resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        // Context without args set.
        let ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        let err = resolver
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect_err("must reject missing args");
        assert!(matches!(err, ResolverError::InvalidShape { .. }));
    }

    #[test]
    fn args_resolver_supports_numeric_and_bool_values() {
        let resolver = ArgsResolver::builder()
            .for_target("api:thing")
            .map("count", "count_label")
            .map("flag", "flag_label")
            .build();

        let ctx = ctx_with_args("agent:jake", json!({ "count": 7, "flag": true }));
        let out = resolver
            .resolve(&ObjectId::new("api:thing"), &Operation::new("call"), &ctx)
            .expect("resolve");
        let by_label: HashMap<_, _> = out
            .iter()
            .map(|d| (d.label.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(by_label["count_label"], "7");
        assert_eq!(by_label["flag_label"], "true");
    }

    #[test]
    fn context_extensions_round_trip_typed_value() {
        struct Session {
            tenant: String,
        }

        let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        ctx.insert(Session {
            tenant: "acme".to_string(),
        });

        let session = ctx.get::<Session>().expect("present");
        assert_eq!(session.tenant, "acme");

        // Querying for a type that wasn't inserted returns None.
        assert!(ctx.get::<u32>().is_none());
    }

    #[test]
    #[should_panic(expected = "for_target")]
    fn map_before_for_target_panics() {
        let _ = ArgsResolver::builder().map("x", "y");
    }
}
