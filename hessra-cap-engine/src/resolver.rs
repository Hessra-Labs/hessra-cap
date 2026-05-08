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
//!   mappings, reading from `ctx.args`.
//! - [`WebappResolver`]: reads from an [`AuthSession`] extension and/or
//!   matches a [`RequestUrl`] extension against `{name}` URL templates.
//! - [`EventResolver`]: reads from an [`Event`] extension via dot-separated
//!   JSON paths.
//! - [`CompositeResolver`]: dispatches to per-target resolvers, with an
//!   optional default for unknown targets.

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

// ---------------------------------------------------------------------------
// CompositeResolver
// ---------------------------------------------------------------------------

/// A resolver that dispatches to per-target resolvers, with an optional
/// default for unknown targets.
///
/// Use this when different targets need different resolution strategies in
/// the same engine. For example: `filesystem:source` uses [`ArgsResolver`],
/// `api:posts` uses [`WebappResolver`].
///
/// # Example
///
/// ```rust,no_run
/// use hessra_cap_engine::{ArgsResolver, CompositeResolver, NoopResolver};
///
/// let composite = CompositeResolver::builder()
///     .add(
///         "filesystem:source",
///         ArgsResolver::builder()
///             .for_target("filesystem:source")
///             .map("path", "path_prefix")
///             .build(),
///     )
///     .with_default(NoopResolver)
///     .build();
/// ```
pub struct CompositeResolver {
    per_target: HashMap<ObjectId, Box<dyn DesignationResolver>>,
    default: Option<Box<dyn DesignationResolver>>,
}

impl CompositeResolver {
    /// Begin building a composite resolver.
    pub fn builder() -> CompositeResolverBuilder {
        CompositeResolverBuilder::default()
    }
}

impl std::fmt::Debug for CompositeResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CompositeResolver")
            .field("targets", &self.per_target.keys().collect::<Vec<_>>())
            .field("has_default", &self.default.is_some())
            .finish()
    }
}

impl DesignationResolver for CompositeResolver {
    fn resolve(
        &self,
        target: &ObjectId,
        operation: &Operation,
        ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError> {
        if let Some(r) = self.per_target.get(target) {
            return r.resolve(target, operation, ctx);
        }
        if let Some(d) = &self.default {
            return d.resolve(target, operation, ctx);
        }
        Ok(Vec::new())
    }
}

/// Builder for [`CompositeResolver`].
#[derive(Default)]
pub struct CompositeResolverBuilder {
    per_target: HashMap<ObjectId, Box<dyn DesignationResolver>>,
    default: Option<Box<dyn DesignationResolver>>,
}

impl CompositeResolverBuilder {
    /// Register a resolver for one specific target. Re-registering replaces
    /// the previous resolver for that target.
    pub fn add<R>(mut self, target: impl Into<ObjectId>, resolver: R) -> Self
    where
        R: DesignationResolver + 'static,
    {
        self.per_target.insert(target.into(), Box::new(resolver));
        self
    }

    /// Set the default resolver used when no per-target entry matches.
    /// Without this, unknown targets resolve to no designations.
    pub fn with_default<R>(mut self, resolver: R) -> Self
    where
        R: DesignationResolver + 'static,
    {
        self.default = Some(Box::new(resolver));
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> CompositeResolver {
        CompositeResolver {
            per_target: self.per_target,
            default: self.default,
        }
    }
}

// ---------------------------------------------------------------------------
// WebappResolver
// ---------------------------------------------------------------------------

/// A flat string-keyed map of session fields a webapp wants to expose to
/// resolvers, inserted into [`DesignationContext`] as a typed extension.
///
/// Webapps populate an `AuthSession` from their own session struct (cookie
/// session, JWT claims, etc.) and call `ctx.insert(session)`. The
/// [`WebappResolver`] reads it back via `ctx.get::<AuthSession>()`.
#[derive(Debug, Default, Clone)]
pub struct AuthSession {
    fields: HashMap<String, String>,
}

impl AuthSession {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.fields.insert(key.into(), value.into());
        self
    }

    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(String::as_str)
    }
}

/// The current request's URL, inserted into [`DesignationContext`] when the
/// webapp wants [`WebappResolver`] to extract designations from it via URL
/// patterns.
#[derive(Debug, Clone)]
pub struct RequestUrl(pub String);

/// A resolver designed for the webapp pattern. Pulls designation values from
/// two sources, both supplied via context extensions:
///
/// - [`AuthSession`] for fields the webapp authenticated (tenant, user, etc.).
/// - [`RequestUrl`] for path segments matched by `{name}` placeholder
///   patterns.
///
/// Both sources are optional per target. The resolver returns whatever it can
/// successfully extract; configured fields that are missing in the session,
/// or URL patterns that don't match the request URL, return
/// [`ResolverError::MissingField`] / [`ResolverError::InvalidShape`].
///
/// # Example
///
/// ```rust,no_run
/// use hessra_cap_engine::WebappResolver;
///
/// let resolver = WebappResolver::builder()
///     .for_target("api:posts")
///     .from_session("tenant_id", "tenant_id")
///     .from_session("user", "user_subject")
///     .from_url_pattern("/tenants/{tenant_id}/posts/{resource_id}")
///     .build();
/// ```
#[derive(Debug, Default, Clone)]
pub struct WebappResolver {
    per_target: HashMap<ObjectId, WebappTargetMappings>,
}

#[derive(Debug, Default, Clone)]
struct WebappTargetMappings {
    /// Pairs of (session_key, designation_label).
    session: Vec<(String, String)>,
    /// URL pattern templates.
    url_patterns: Vec<UrlPattern>,
}

#[derive(Debug, Clone)]
struct UrlPattern {
    /// Compiled pattern segments.
    segments: Vec<UrlSegment>,
}

#[derive(Debug, Clone)]
enum UrlSegment {
    Literal(String),
    Capture(String),
}

impl UrlPattern {
    fn parse(pattern: &str) -> Self {
        let segments = pattern
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|seg| {
                if seg.starts_with('{') && seg.ends_with('}') {
                    UrlSegment::Capture(seg[1..seg.len() - 1].to_string())
                } else {
                    UrlSegment::Literal(seg.to_string())
                }
            })
            .collect();
        Self { segments }
    }

    /// Match the pattern against a URL path; returns the named captures if
    /// the pattern matches, or `None` if it doesn't.
    fn match_url(&self, url: &str) -> Option<Vec<(String, String)>> {
        let url_segments: Vec<&str> = url
            .trim_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .collect();
        if url_segments.len() != self.segments.len() {
            return None;
        }
        let mut captures = Vec::new();
        for (pat, val) in self.segments.iter().zip(url_segments.iter()) {
            match pat {
                UrlSegment::Literal(lit) => {
                    if lit != val {
                        return None;
                    }
                }
                UrlSegment::Capture(name) => {
                    captures.push((name.clone(), (*val).to_string()));
                }
            }
        }
        Some(captures)
    }
}

impl WebappResolver {
    pub fn builder() -> WebappResolverBuilder {
        WebappResolverBuilder::default()
    }
}

impl DesignationResolver for WebappResolver {
    fn resolve(
        &self,
        target: &ObjectId,
        _operation: &Operation,
        ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError> {
        let Some(mappings) = self.per_target.get(target) else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();

        if !mappings.session.is_empty() {
            let session = ctx
                .get::<AuthSession>()
                .ok_or_else(|| ResolverError::InvalidShape {
                    reason: format!(
                        "WebappResolver needs AuthSession in the context for target '{target}'",
                    ),
                })?;
            for (key, label) in &mappings.session {
                let value = session
                    .get(key)
                    .ok_or_else(|| ResolverError::MissingField {
                        label: label.clone(),
                        detail: format!("session key '{key}' not present"),
                    })?;
                out.push(Designation {
                    label: label.clone(),
                    value: value.to_string(),
                });
            }
        }

        if !mappings.url_patterns.is_empty() {
            let url = ctx.get::<RequestUrl>().ok_or_else(|| ResolverError::InvalidShape {
                reason: format!(
                    "WebappResolver has URL patterns for target '{target}' but no RequestUrl in context",
                ),
            })?;
            // Try each pattern in order; first match wins.
            let mut matched = false;
            for pattern in &mappings.url_patterns {
                if let Some(captures) = pattern.match_url(&url.0) {
                    for (name, value) in captures {
                        out.push(Designation { label: name, value });
                    }
                    matched = true;
                    break;
                }
            }
            if !matched {
                return Err(ResolverError::InvalidShape {
                    reason: format!(
                        "WebappResolver: no URL pattern for target '{target}' matched request '{}'",
                        url.0,
                    ),
                });
            }
        }

        Ok(out)
    }
}

/// Builder for [`WebappResolver`].
#[derive(Debug, Default)]
pub struct WebappResolverBuilder {
    per_target: HashMap<ObjectId, WebappTargetMappings>,
    current: Option<ObjectId>,
}

impl WebappResolverBuilder {
    /// Set the target for subsequent `.from_session()` and
    /// `.from_url_pattern()` calls.
    pub fn for_target(mut self, target: impl Into<ObjectId>) -> Self {
        let id = target.into();
        self.per_target.entry(id.clone()).or_default();
        self.current = Some(id);
        self
    }

    /// Map a session field key to a designation label.
    pub fn from_session(
        mut self,
        session_key: impl Into<String>,
        label: impl Into<String>,
    ) -> Self {
        let current = self
            .current
            .as_ref()
            .expect("WebappResolverBuilder::from_session called before for_target()");
        self.per_target
            .get_mut(current)
            .expect("for_target inserted an empty entry")
            .session
            .push((session_key.into(), label.into()));
        self
    }

    /// Add a URL pattern to match against the [`RequestUrl`] in the context.
    /// Each `{name}` placeholder in the pattern becomes a designation with
    /// the captured value, labeled by the placeholder name.
    pub fn from_url_pattern(mut self, pattern: impl AsRef<str>) -> Self {
        let current = self
            .current
            .as_ref()
            .expect("WebappResolverBuilder::from_url_pattern called before for_target()");
        let parsed = UrlPattern::parse(pattern.as_ref());
        self.per_target
            .get_mut(current)
            .expect("for_target inserted an empty entry")
            .url_patterns
            .push(parsed);
        self
    }

    pub fn build(self) -> WebappResolver {
        WebappResolver {
            per_target: self.per_target,
        }
    }
}

// ---------------------------------------------------------------------------
// EventResolver
// ---------------------------------------------------------------------------

/// An event payload (typically an inbound webhook or gateway message)
/// inserted into [`DesignationContext`] as a typed extension. The
/// [`EventResolver`] reads fields from this value to produce designations.
#[derive(Debug, Clone)]
pub struct Event(pub serde_json::Value);

/// A resolver for event-driven principals: pulls designation values from a
/// JSON [`Event`] in the context, mapping event field names to designation
/// labels per target.
///
/// Same shape as [`ArgsResolver`] but reads from `ctx.get::<Event>()` rather
/// than `ctx.args`. Use this when the trigger for a mint is an external event
/// (Discord gateway message, GitHub webhook) and the relevant designation
/// values live on the event's payload.
///
/// # Example
///
/// ```rust,no_run
/// use hessra_cap_engine::EventResolver;
///
/// let resolver = EventResolver::builder()
///     .for_target("tool:discord-dm")
///     .map("user.id", "user_id")
///     .build();
/// ```
#[derive(Debug, Default, Clone)]
pub struct EventResolver {
    per_target: HashMap<ObjectId, HashMap<String, String>>,
}

impl EventResolver {
    pub fn builder() -> EventResolverBuilder {
        EventResolverBuilder::default()
    }
}

impl DesignationResolver for EventResolver {
    fn resolve(
        &self,
        target: &ObjectId,
        _operation: &Operation,
        ctx: &DesignationContext,
    ) -> Result<Vec<Designation>, ResolverError> {
        let Some(mappings) = self.per_target.get(target) else {
            return Ok(Vec::new());
        };
        if mappings.is_empty() {
            return Ok(Vec::new());
        }

        let event = ctx
            .get::<Event>()
            .ok_or_else(|| ResolverError::InvalidShape {
                reason: format!("EventResolver needs Event in the context for target '{target}'",),
            })?;

        let mut out = Vec::with_capacity(mappings.len());
        for (event_path, label) in mappings {
            let value = lookup_json_path(&event.0, event_path).ok_or_else(|| {
                ResolverError::MissingField {
                    label: label.clone(),
                    detail: format!("event path '{event_path}' not present"),
                }
            })?;
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Number(n) => n.to_string(),
                serde_json::Value::Bool(b) => b.to_string(),
                other => {
                    return Err(ResolverError::InvalidShape {
                        reason: format!(
                            "event path '{event_path}' for designation '{label}' must be a string, number, or bool, got {}",
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

/// Look up a dot-separated path inside a JSON value (e.g., `"user.id"`).
/// Each segment is treated as an object key. Returns `None` if any segment
/// is missing or any intermediate value is not an object.
fn lookup_json_path<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.as_object()?.get(segment)?;
    }
    Some(current)
}

/// Builder for [`EventResolver`].
#[derive(Debug, Default)]
pub struct EventResolverBuilder {
    per_target: HashMap<ObjectId, HashMap<String, String>>,
    current: Option<ObjectId>,
}

impl EventResolverBuilder {
    pub fn for_target(mut self, target: impl Into<ObjectId>) -> Self {
        let id = target.into();
        self.per_target.entry(id.clone()).or_default();
        self.current = Some(id);
        self
    }

    /// Map an event field path (dot-separated) to a designation label.
    pub fn map(mut self, event_path: impl Into<String>, label: impl Into<String>) -> Self {
        let current = self
            .current
            .as_ref()
            .expect("EventResolverBuilder::map called before for_target()");
        self.per_target
            .get_mut(current)
            .expect("for_target inserted an empty map")
            .insert(event_path.into(), label.into());
        self
    }

    pub fn build(self) -> EventResolver {
        EventResolver {
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

    // =====================================================================
    // CompositeResolver
    // =====================================================================

    #[test]
    fn composite_dispatches_to_per_target_resolver() {
        let fs_resolver = ArgsResolver::builder()
            .for_target("filesystem:source")
            .map("path", "path_prefix")
            .build();

        let composite = CompositeResolver::builder()
            .add("filesystem:source", fs_resolver)
            .build();

        let ctx = ctx_with_args("agent:jake", json!({ "path": "code/hessra/" }));
        let out = composite
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "path_prefix");
    }

    #[test]
    fn composite_unknown_target_returns_empty_when_no_default() {
        let composite = CompositeResolver::builder()
            .add(
                "filesystem:source",
                ArgsResolver::builder()
                    .for_target("filesystem:source")
                    .map("path", "path_prefix")
                    .build(),
            )
            .build();

        let ctx = ctx_with_args("agent:jake", json!({}));
        let out = composite
            .resolve(
                &ObjectId::new("tool:other"),
                &Operation::new("invoke"),
                &ctx,
            )
            .expect("resolve");
        assert!(out.is_empty());
    }

    #[test]
    fn composite_default_handles_unknown_targets() {
        struct ConstResolver;
        impl DesignationResolver for ConstResolver {
            fn resolve(
                &self,
                _t: &ObjectId,
                _op: &Operation,
                _ctx: &DesignationContext,
            ) -> Result<Vec<Designation>, ResolverError> {
                Ok(vec![Designation {
                    label: "default_label".into(),
                    value: "default_value".into(),
                }])
            }
        }

        let composite = CompositeResolver::builder()
            .add(
                "filesystem:source",
                ArgsResolver::builder()
                    .for_target("filesystem:source")
                    .map("path", "path_prefix")
                    .build(),
            )
            .with_default(ConstResolver)
            .build();

        // Unknown target falls through to the default.
        let ctx = ctx_with_args("agent:jake", json!({}));
        let out = composite
            .resolve(&ObjectId::new("tool:other"), &Operation::new("op"), &ctx)
            .expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "default_label");

        // Known target uses the per-target resolver, not the default.
        let ctx = ctx_with_args("agent:jake", json!({ "path": "/x" }));
        let out = composite
            .resolve(
                &ObjectId::new("filesystem:source"),
                &Operation::new("read"),
                &ctx,
            )
            .expect("resolve");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "path_prefix");
    }

    // =====================================================================
    // WebappResolver
    // =====================================================================

    #[test]
    fn webapp_resolver_extracts_session_fields() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_session("tenant_id", "tenant_id")
            .from_session("user", "user_subject")
            .build();

        let session = AuthSession::new()
            .with("tenant_id", "acme")
            .with("user", "alice");

        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(session);

        let out = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect("resolve");
        let by_label: HashMap<_, _> = out
            .iter()
            .map(|d| (d.label.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(by_label["tenant_id"], "acme");
        assert_eq!(by_label["user_subject"], "alice");
    }

    #[test]
    fn webapp_resolver_missing_session_errors() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_session("tenant_id", "tenant_id")
            .build();

        let ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        let err = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect_err("must fail without session");
        assert!(matches!(err, ResolverError::InvalidShape { .. }));
    }

    #[test]
    fn webapp_resolver_missing_session_field_errors() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_session("tenant_id", "tenant_id")
            .build();

        let session = AuthSession::new().with("other", "x");
        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(session);

        let err = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect_err("must fail with missing field");
        match err {
            ResolverError::MissingField { label, .. } => assert_eq!(label, "tenant_id"),
            other => panic!("wrong variant: {other:?}"),
        }
    }

    #[test]
    fn webapp_resolver_url_pattern_extracts_named_captures() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_url_pattern("/tenants/{tenant_id}/posts/{resource_id}")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(RequestUrl("/tenants/acme/posts/p-42".to_string()));

        let out = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect("resolve");
        let by_label: HashMap<_, _> = out
            .iter()
            .map(|d| (d.label.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(by_label["tenant_id"], "acme");
        assert_eq!(by_label["resource_id"], "p-42");
    }

    #[test]
    fn webapp_resolver_url_pattern_no_match_errors() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_url_pattern("/tenants/{tenant_id}/posts/{resource_id}")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(RequestUrl("/wrong/shape".to_string()));

        let err = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect_err("pattern must not match");
        assert!(matches!(err, ResolverError::InvalidShape { .. }));
    }

    #[test]
    fn webapp_resolver_first_matching_pattern_wins() {
        // Multiple patterns: longer/more-specific first; shorter as fallback.
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_url_pattern("/tenants/{tenant_id}/posts/{resource_id}")
            .from_url_pattern("/tenants/{tenant_id}/posts")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(RequestUrl("/tenants/acme/posts".to_string()));

        let out = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect("second pattern matches");
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].label, "tenant_id");
        assert_eq!(out[0].value, "acme");
    }

    #[test]
    fn webapp_resolver_combines_session_and_url() {
        let resolver = WebappResolver::builder()
            .for_target("api:posts")
            .from_session("user", "user_subject")
            .from_url_pattern("/tenants/{tenant_id}")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
        ctx.insert(AuthSession::new().with("user", "alice"));
        ctx.insert(RequestUrl("/tenants/acme".to_string()));

        let out = resolver
            .resolve(&ObjectId::new("api:posts"), &Operation::new("read"), &ctx)
            .expect("resolve");
        let by_label: HashMap<_, _> = out
            .iter()
            .map(|d| (d.label.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(by_label["user_subject"], "alice");
        assert_eq!(by_label["tenant_id"], "acme");
    }

    // =====================================================================
    // EventResolver
    // =====================================================================

    #[test]
    fn event_resolver_extracts_top_level_field() {
        let resolver = EventResolver::builder()
            .for_target("tool:discord-dm")
            .map("user_id", "user_id")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        ctx.insert(Event(json!({ "user_id": "u-42" })));

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
    fn event_resolver_extracts_dotted_path() {
        let resolver = EventResolver::builder()
            .for_target("tool:discord-dm")
            .map("user.id", "user_id")
            .map("channel.id", "channel_id")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        ctx.insert(Event(json!({
            "user": { "id": "u-42", "name": "alice" },
            "channel": { "id": "c-7" },
        })));

        let out = resolver
            .resolve(
                &ObjectId::new("tool:discord-dm"),
                &Operation::new("send"),
                &ctx,
            )
            .expect("resolve");
        let by_label: HashMap<_, _> = out
            .iter()
            .map(|d| (d.label.as_str(), d.value.as_str()))
            .collect();
        assert_eq!(by_label["user_id"], "u-42");
        assert_eq!(by_label["channel_id"], "c-7");
    }

    #[test]
    fn event_resolver_missing_event_errors() {
        let resolver = EventResolver::builder()
            .for_target("tool:discord-dm")
            .map("user_id", "user_id")
            .build();

        let ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        let err = resolver
            .resolve(
                &ObjectId::new("tool:discord-dm"),
                &Operation::new("send"),
                &ctx,
            )
            .expect_err("must fail without event");
        assert!(matches!(err, ResolverError::InvalidShape { .. }));
    }

    #[test]
    fn event_resolver_missing_event_field_errors() {
        let resolver = EventResolver::builder()
            .for_target("tool:discord-dm")
            .map("user_id", "user_id")
            .build();

        let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
        ctx.insert(Event(json!({ "other": "x" })));

        let err = resolver
            .resolve(
                &ObjectId::new("tool:discord-dm"),
                &Operation::new("send"),
                &ctx,
            )
            .expect_err("must fail with missing path");
        match err {
            ResolverError::MissingField { label, .. } => assert_eq!(label, "user_id"),
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
