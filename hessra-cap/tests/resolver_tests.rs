//! Integration tests for the DesignationResolver wiring on CapabilityEngine.

use hessra_cap::{
    ArgsResolver, AuthSession, CListPolicy, CapabilityEngine, CompositeResolver, Designation,
    DesignationContext, DesignationResolver, EngineError, Event, EventResolver, ObjectId,
    Operation, RequestUrl, ResolverError, SchemaRegistry, WebappResolver,
};
use serde_json::json;

fn schema_filesystem_path_prefix() -> SchemaRegistry {
    SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read", required_designations = ["path_prefix"] },
]
"#,
    )
    .expect("schema parses")
}

fn jake_can_read_filesystem_source() -> CListPolicy {
    CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"] },
]
"#,
    )
    .expect("policy parses")
}

#[test]
fn mint_with_context_succeeds_when_resolver_covers_required() {
    let resolver = ArgsResolver::builder()
        .for_target("filesystem:source")
        .map("path", "path_prefix")
        .build();

    let engine = CapabilityEngine::with_generated_keys(jake_can_read_filesystem_source())
        .with_schema(schema_filesystem_path_prefix())
        .expect("schema attaches")
        .with_resolver(resolver);

    let ctx = DesignationContext::new(ObjectId::new("agent:jake"))
        .with_args(json!({ "path": "code/hessra/" }));

    let result = engine
        .mint_with_context(
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &ctx,
            None,
        )
        .expect("mint succeeds");

    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "path_prefix".into(),
                value: "code/hessra/".into(),
            }],
        )
        .expect("verify with resolver-supplied designation succeeds");
}

#[test]
fn mint_with_context_errors_when_resolver_returns_insufficient() {
    let resolver = ArgsResolver::builder()
        .for_target("filesystem:source")
        .map("path", "path_prefix")
        .build();

    let engine = CapabilityEngine::with_generated_keys(jake_can_read_filesystem_source())
        .with_schema(schema_filesystem_path_prefix())
        .expect("schema attaches")
        .with_resolver(resolver);

    // Args are missing the `path` field, so the resolver returns MissingField.
    let ctx = DesignationContext::new(ObjectId::new("agent:jake")).with_args(json!({ "other": 1 }));

    let err = match engine.mint_with_context(
        &ObjectId::new("filesystem:source"),
        &Operation::new("read"),
        &ctx,
        None,
    ) {
        Ok(_) => panic!("expected resolver to fail"),
        Err(e) => e,
    };

    assert!(
        matches!(
            err,
            EngineError::Resolver(ResolverError::MissingField { .. })
        ),
        "expected EngineError::Resolver(MissingField), got {err:?}",
    );
    assert!(err.to_string().contains("path_prefix"));
}

#[test]
fn mint_with_context_combines_static_and_resolver_designations() {
    // Schema requires both `channel` and `tag`. Policy supplies `channel`
    // statically; resolver supplies `tag` from args.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "tool:tagged-channel", operations = ["post"], designations = [{ label = "channel", value = "engineering" }] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "tool:tagged-channel"
operations = [
  { name = "post", required_designations = ["channel", "tag"] },
]
"#,
    )
    .expect("schema parses");

    let resolver = ArgsResolver::builder()
        .for_target("tool:tagged-channel")
        .map("tag", "tag")
        .build();

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(resolver);

    let ctx =
        DesignationContext::new(ObjectId::new("agent:jake")).with_args(json!({ "tag": "release" }));

    let result = engine
        .mint_with_context(
            &ObjectId::new("tool:tagged-channel"),
            &Operation::new("post"),
            &ctx,
            None,
        )
        .expect("mint succeeds: static + resolver covers required");

    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("tool:tagged-channel"),
            &Operation::new("post"),
            &[
                Designation {
                    label: "channel".into(),
                    value: "engineering".into(),
                },
                Designation {
                    label: "tag".into(),
                    value: "release".into(),
                },
            ],
        )
        .expect("verify with both designations succeeds");
}

#[test]
fn mint_with_context_with_noop_resolver_falls_back_to_required_check() {
    // Default resolver returns no designations. Schema requires path_prefix
    // and the engine errors with MissingRequiredDesignation rather than a
    // resolver error.
    let engine = CapabilityEngine::with_generated_keys(jake_can_read_filesystem_source())
        .with_schema(schema_filesystem_path_prefix())
        .expect("schema attaches");

    let ctx = DesignationContext::new(ObjectId::new("agent:jake"));

    let err = match engine.mint_with_context(
        &ObjectId::new("filesystem:source"),
        &Operation::new("read"),
        &ctx,
        None,
    ) {
        Ok(_) => panic!("expected mint to fail"),
        Err(e) => e,
    };

    assert!(
        matches!(err, EngineError::MissingRequiredDesignation { .. }),
        "expected MissingRequiredDesignation, got {err:?}",
    );
}

#[test]
fn custom_resolver_via_trait_object() {
    // A consumer can implement DesignationResolver themselves and plug it in.
    struct ConstResolver {
        label: &'static str,
        value: &'static str,
    }

    impl DesignationResolver for ConstResolver {
        fn resolve(
            &self,
            _target: &ObjectId,
            _operation: &Operation,
            _ctx: &DesignationContext,
        ) -> Result<Vec<Designation>, ResolverError> {
            Ok(vec![Designation {
                label: self.label.to_string(),
                value: self.value.to_string(),
            }])
        }
    }

    let engine = CapabilityEngine::with_generated_keys(jake_can_read_filesystem_source())
        .with_schema(schema_filesystem_path_prefix())
        .expect("schema attaches")
        .with_resolver(ConstResolver {
            label: "path_prefix",
            value: "constant/value",
        });

    let ctx = DesignationContext::new(ObjectId::new("agent:jake"));
    let result = engine
        .mint_with_context(
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &ctx,
            None,
        )
        .expect("mint succeeds");

    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "path_prefix".into(),
                value: "constant/value".into(),
            }],
        )
        .expect("verify with constant designation");
}

#[test]
fn extension_bag_passes_typed_data_through_to_resolver() {
    // A resolver reads a typed extension from the context. Demonstrates the
    // `WebappResolver`-style pattern: the auth session lives as an extension.
    #[derive(Debug)]
    struct Session {
        tenant: String,
    }

    struct SessionResolver;

    impl DesignationResolver for SessionResolver {
        fn resolve(
            &self,
            _target: &ObjectId,
            _operation: &Operation,
            ctx: &DesignationContext,
        ) -> Result<Vec<Designation>, ResolverError> {
            let session = ctx
                .get::<Session>()
                .ok_or_else(|| ResolverError::InvalidShape {
                    reason: "Session extension not present on context".to_string(),
                })?;
            Ok(vec![Designation {
                label: "tenant_id".into(),
                value: session.tenant.clone(),
            }])
        }
    }

    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "service:webapp"
capabilities = [
    { target = "api:posts", operations = ["read"] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "api:posts"
operations = [
  { name = "read", required_designations = ["tenant_id"] },
]
"#,
    )
    .expect("schema parses");

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(SessionResolver);

    let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
    ctx.insert(Session {
        tenant: "acme-corp".to_string(),
    });

    let result = engine
        .mint_with_context(
            &ObjectId::new("api:posts"),
            &Operation::new("read"),
            &ctx,
            None,
        )
        .expect("mint succeeds");

    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("api:posts"),
            &Operation::new("read"),
            &[Designation {
                label: "tenant_id".into(),
                value: "acme-corp".into(),
            }],
        )
        .expect("verify with the session-supplied tenant_id");
}

// ---------------------------------------------------------------------------
// CompositeResolver
// ---------------------------------------------------------------------------

#[test]
fn composite_routes_per_target_through_engine() {
    // Two targets in the same engine, each handled by a different resolver.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"] },
    { target = "tool:discord-dm", operations = ["send"] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "filesystem:source"
operations = [{ name = "read", required_designations = ["path_prefix"] }]

[[targets]]
id = "tool:discord-dm"
operations = [{ name = "send", required_designations = ["user_id"] }]
"#,
    )
    .expect("schema parses");

    let composite = CompositeResolver::builder()
        .add(
            "filesystem:source",
            ArgsResolver::builder()
                .for_target("filesystem:source")
                .map("path", "path_prefix")
                .build(),
        )
        .add(
            "tool:discord-dm",
            EventResolver::builder()
                .for_target("tool:discord-dm")
                .map("user.id", "user_id")
                .build(),
        )
        .build();

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(composite);

    // filesystem:source: ArgsResolver wins, reads from ctx.args.
    let ctx_fs = DesignationContext::new(ObjectId::new("agent:jake"))
        .with_args(json!({ "path": "code/hessra/" }));
    let result = engine
        .mint_with_context(
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &ctx_fs,
            None,
        )
        .expect("filesystem mint");
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "path_prefix".into(),
                value: "code/hessra/".into(),
            }],
        )
        .expect("verify filesystem cap");

    // tool:discord-dm: EventResolver wins, reads from Event extension.
    let mut ctx_discord = DesignationContext::new(ObjectId::new("agent:jake"));
    ctx_discord.insert(Event(json!({ "user": { "id": "u-7" } })));
    let result = engine
        .mint_with_context(
            &ObjectId::new("tool:discord-dm"),
            &Operation::new("send"),
            &ctx_discord,
            None,
        )
        .expect("discord mint");
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("tool:discord-dm"),
            &Operation::new("send"),
            &[Designation {
                label: "user_id".into(),
                value: "u-7".into(),
            }],
        )
        .expect("verify discord cap");
}

// ---------------------------------------------------------------------------
// WebappResolver
// ---------------------------------------------------------------------------

#[test]
fn webapp_resolver_session_plus_url_pattern_through_engine() {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "service:webapp"
capabilities = [
    { target = "api:posts", operations = ["delete"] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "api:posts"
operations = [
  { name = "delete", required_designations = ["tenant_id", "user_subject", "resource_id"] },
]
"#,
    )
    .expect("schema parses");

    // tenant_id and user_subject from the session; resource_id from the URL.
    let resolver = WebappResolver::builder()
        .for_target("api:posts")
        .from_session("tenant_id", "tenant_id")
        .from_session("user", "user_subject")
        .from_url_pattern("/tenants/{tenant_id}/posts/{resource_id}")
        .build();

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(resolver);

    let mut ctx = DesignationContext::new(ObjectId::new("service:webapp"));
    ctx.insert(
        AuthSession::new()
            .with("tenant_id", "acme")
            .with("user", "alice"),
    );
    ctx.insert(RequestUrl("/tenants/acme/posts/p-42".to_string()));

    let result = engine
        .mint_with_context(
            &ObjectId::new("api:posts"),
            &Operation::new("delete"),
            &ctx,
            None,
        )
        .expect("mint succeeds");

    // Note: tenant_id appears twice (session + URL) which is fine; both
    // produce the same "tenant_id" designation with the same value, and the
    // verifier only needs one matching fact per check.
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("api:posts"),
            &Operation::new("delete"),
            &[
                Designation {
                    label: "tenant_id".into(),
                    value: "acme".into(),
                },
                Designation {
                    label: "user_subject".into(),
                    value: "alice".into(),
                },
                Designation {
                    label: "resource_id".into(),
                    value: "p-42".into(),
                },
            ],
        )
        .expect("verify webapp cap");
}

// ---------------------------------------------------------------------------
// EventResolver
// ---------------------------------------------------------------------------

#[test]
fn event_resolver_dotted_path_through_engine() {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "tool:discord-dm", operations = ["send"] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "tool:discord-dm"
operations = [
  { name = "send", required_designations = ["user_id", "channel_id"] },
]
"#,
    )
    .expect("schema parses");

    let resolver = EventResolver::builder()
        .for_target("tool:discord-dm")
        .map("user.id", "user_id")
        .map("channel.id", "channel_id")
        .build();

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(resolver);

    let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
    ctx.insert(Event(json!({
        "user": { "id": "u-42", "name": "alice" },
        "channel": { "id": "c-7", "kind": "dm" },
    })));

    let result = engine
        .mint_with_context(
            &ObjectId::new("tool:discord-dm"),
            &Operation::new("send"),
            &ctx,
            None,
        )
        .expect("mint succeeds");

    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("tool:discord-dm"),
            &Operation::new("send"),
            &[
                Designation {
                    label: "user_id".into(),
                    value: "u-42".into(),
                },
                Designation {
                    label: "channel_id".into(),
                    value: "c-7".into(),
                },
            ],
        )
        .expect("verify discord cap");
}

#[test]
fn event_resolver_missing_path_propagates_as_engine_error() {
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "tool:discord-dm", operations = ["send"] },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "tool:discord-dm"
operations = [
  { name = "send", required_designations = ["user_id"] },
]
"#,
    )
    .expect("schema parses");

    let resolver = EventResolver::builder()
        .for_target("tool:discord-dm")
        .map("user.id", "user_id")
        .build();

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("schema attaches")
        .with_resolver(resolver);

    let mut ctx = DesignationContext::new(ObjectId::new("agent:jake"));
    ctx.insert(Event(json!({ "user": {} })));

    let err = match engine.mint_with_context(
        &ObjectId::new("tool:discord-dm"),
        &Operation::new("send"),
        &ctx,
        None,
    ) {
        Ok(_) => panic!("expected resolver error"),
        Err(e) => e,
    };
    assert!(
        matches!(
            err,
            EngineError::Resolver(ResolverError::MissingField { .. })
        ),
        "expected EngineError::Resolver(MissingField), got {err:?}",
    );
}
