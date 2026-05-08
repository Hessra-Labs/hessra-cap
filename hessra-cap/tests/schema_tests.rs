//! Integration tests for the schema layer wired into the engine.

use hessra_cap::{
    CListPolicy, CapabilityEngine, Designation, ObjectId, Operation, SchemaError, SchemaRegistry,
};

fn schema_with_filesystem_source() -> SchemaRegistry {
    SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read",  required_designations = ["path_prefix"] },
  { name = "write", required_designations = ["path_prefix"] },
]
"#,
    )
    .expect("schema parses")
}

#[test]
fn from_dir_loads_multiple_files_and_merges_targets() {
    let dir = tempdir();

    write_file(
        &dir,
        "filesystem.toml",
        r#"
[[targets]]
id = "filesystem:source"
operations = [{ name = "read", required_designations = ["path_prefix"] }]
"#,
    );

    write_file(
        &dir,
        "discord.toml",
        r#"
[[targets]]
id = "tool:discord-dm"
operations = [{ name = "send", required_designations = ["user_id"] }]
"#,
    );

    write_file(
        &dir,
        "history.toml",
        r#"
[[targets]]
id = "tool:conversation-archive"
operations = [{ name = "read", required_designations = ["conversation_id"] }]
"#,
    );

    let reg = SchemaRegistry::from_dir(dir.path()).expect("loads");
    assert_eq!(reg.targets().count(), 3);
    assert!(reg.get("filesystem:source").is_some());
    assert!(reg.get("tool:discord-dm").is_some());
    assert!(reg.get("tool:conversation-archive").is_some());
    assert_eq!(
        reg.required_designations("tool:discord-dm", "send"),
        Some(["user_id".to_string()].as_ref()),
    );
}

#[test]
fn from_dir_rejects_duplicate_target_across_files() {
    let dir = tempdir();
    write_file(
        &dir,
        "a.toml",
        r#"
[[targets]]
id = "filesystem:source"
operations = []
"#,
    );
    write_file(
        &dir,
        "b.toml",
        r#"
[[targets]]
id = "filesystem:source"
operations = []
"#,
    );

    let err = SchemaRegistry::from_dir(dir.path()).expect_err("duplicate target");
    match err {
        SchemaError::DuplicateTarget { id, .. } => assert_eq!(id, "filesystem:source"),
        other => panic!("wrong error: {other:?}"),
    }
}

#[test]
fn engine_with_schema_enforces_required_designations() {
    // Policy grants agent:openclaw read on filesystem:source. The schema
    // requires path_prefix. Without that designation, mint must fail.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:openclaw"
capabilities = [
    { target = "filesystem:source", operations = ["read"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema_with_filesystem_source())
        .expect("engine constructs");

    // No designations supplied: missing path_prefix.
    let err = match engine.mint_capability(
        &ObjectId::new("agent:openclaw"),
        &ObjectId::new("filesystem:source"),
        &Operation::new("read"),
        None,
    ) {
        Ok(_) => panic!("expected mint to fail with missing required designation"),
        Err(e) => e,
    };
    let msg = err.to_string();
    assert!(msg.contains("path_prefix"), "error names the label: {msg}");

    // With path_prefix supplied, mint succeeds.
    let result = engine
        .mint_designated_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "path_prefix".into(),
                value: "code/hessra/".into(),
            }],
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
        .expect("verify with the path_prefix designation succeeds");
}

#[test]
fn empty_schema_preserves_today_behavior() {
    // No schema attached: mint with no designations succeeds even on a target
    // a hypothetical schema would require designations for. This is the
    // "no enforcement runs" case.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:openclaw"
capabilities = [
    { target = "tool:file-read", operations = ["invoke"] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy);

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:openclaw"),
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
            None,
        )
        .expect("mint succeeds without schema enforcement");

    engine
        .verify_capability(
            &result.token,
            &ObjectId::new("tool:file-read"),
            &Operation::new("invoke"),
        )
        .expect("verify succeeds");
}

#[test]
fn anchor_designation_is_not_subject_to_required_designations() {
    // Schema's required_designations cannot include "anchor" (rejected at
    // load time). Anchor is set by the policy's anchor_to_subject and goes
    // through its dedicated path. We confirm that an anchor-bound capability
    // mints cleanly when the schema requires no other designations.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"], anchor_to_subject = true },
]
"#,
    )
    .expect("policy parses");

    let schema = SchemaRegistry::from_toml(
        r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read", required_designations = ["path_prefix"] },
]
"#,
    )
    .expect("schema parses");

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("engine constructs");

    let result = engine
        .mint_designated_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[Designation {
                label: "path_prefix".into(),
                value: "code/hessra/".into(),
            }],
            None,
        )
        .expect("mint succeeds with path_prefix; anchor is automatic");

    // The verifier must assert "I am agent:jake" via the anchor designation
    // alongside the path_prefix.
    engine
        .verify_designated_capability(
            &result.token,
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            &[
                Designation {
                    label: "anchor".into(),
                    value: "agent:jake".into(),
                },
                Designation {
                    label: "path_prefix".into(),
                    value: "code/hessra/".into(),
                },
            ],
        )
        .expect("verify with both anchor and path_prefix succeeds");
}

#[test]
fn policy_static_designations_satisfy_required_designations() {
    // Jake's policy declares static designations that fully cover the
    // schema's requirements; the caller supplies nothing extra and mint
    // still succeeds.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"], designations = [{ label = "path_prefix", value = "code/hessra/" }] },
]
"#,
    )
    .expect("policy parses");

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema_with_filesystem_source())
        .expect("engine constructs");

    let result = engine
        .mint_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("filesystem:source"),
            &Operation::new("read"),
            None,
        )
        .expect("mint succeeds: static designations cover required");

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
        .expect("verify with the static-declared path_prefix succeeds");
}

#[test]
fn cross_validation_rejects_unknown_label_in_policy() {
    // Policy declares a static designation for a label that is not in the
    // schema's required_designations. Engine construction must fail.
    let policy = CListPolicy::from_toml(
        r#"
[[objects]]
id = "agent:jake"
capabilities = [
    { target = "filesystem:source", operations = ["read"], designations = [{ label = "totally_unknown_label", value = "x" }] },
]
"#,
    )
    .expect("policy parses");

    let result =
        CapabilityEngine::with_generated_keys(policy).with_schema(schema_with_filesystem_source());

    let err = result
        .map(|_| ())
        .expect_err("engine construction must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("totally_unknown_label"),
        "error names the offending label: {msg}",
    );
}

#[test]
fn caller_designations_combine_with_static_designations() {
    // Policy declares one static designation; schema requires two; caller
    // supplies the second. Mint succeeds because the union covers required.
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

    let engine = CapabilityEngine::with_generated_keys(policy)
        .with_schema(schema)
        .expect("engine constructs");

    let result = engine
        .mint_designated_capability(
            &ObjectId::new("agent:jake"),
            &ObjectId::new("tool:tagged-channel"),
            &Operation::new("post"),
            &[Designation {
                label: "tag".into(),
                value: "release".into(),
            }],
            None,
        )
        .expect("mint succeeds: union covers required");

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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

struct TempDir {
    path: std::path::PathBuf,
}

impl TempDir {
    fn path(&self) -> &std::path::Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn tempdir() -> TempDir {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "hessra-cap-schema-tests-{}-{}",
        std::process::id(),
        n
    ));
    std::fs::create_dir_all(&path).expect("create tempdir");
    TempDir { path }
}

fn write_file(dir: &TempDir, name: &str, contents: &str) {
    std::fs::write(dir.path().join(name), contents).expect("write");
}
