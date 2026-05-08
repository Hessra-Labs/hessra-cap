//! # Hessra Capability Schema
//!
//! Declarative schemas for principals that own targets in a Hessra deployment.
//! A schema names the targets a principal owns, the operations on each target,
//! and the designations the principal requires at mint time for each operation.
//!
//! Schemas are policy-side configuration: they tell the capability engine
//! "the engine refuses to mint a capability for this target/operation unless
//! these designations are attached." This is the issuer-side guard against
//! silently broadening capabilities by forgetting to designate.
//!
//! ## Reserved labels
//!
//! Some designation labels are reserved for engine-built-in semantics and
//! cannot appear in `required_designations`. The schema validator rejects
//! them at load time with [`SchemaError::ReservedLabel`]. Currently:
//!
//! - `"anchor"`: the principal that can verify a capability. Configured via
//!   policy (`anchor_to_subject = true` or `anchor = "<principal>"`) or via
//!   `MintOptions.anchor`. Implemented in the token using the same designation
//!   mechanism as application labels but treated as a distinct concept.
//! - `"facet"`: a per-capability ULID-style identifier the engine attaches
//!   when forwarding facets are enabled. Pairs with an in-memory map the
//!   issuer-and-verifier engine consults, giving per-cap revocation and
//!   single-use-on-ack semantics.
//!
//! See [`RESERVED_LABELS`].

use serde::Deserialize;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Designation labels that the engine handles through dedicated paths and
/// must not appear in any operation's `required_designations`.
///
/// When a new label is added here it must also be wired through the engine's
/// dedicated path. Adding a string to this constant alone is not enough.
pub const RESERVED_LABELS: &[&str] = &["anchor", "facet"];

/// The schema for a single target object: the operations it exposes and the
/// designations each operation requires.
#[derive(Debug, Clone, Deserialize)]
pub struct TargetSchema {
    /// The target's object id (e.g., `"filesystem:source"`).
    pub id: String,
    /// Operations the target exposes.
    #[serde(default)]
    pub operations: Vec<OperationSchema>,
}

/// The schema for a single operation on a target.
#[derive(Debug, Clone, Deserialize)]
pub struct OperationSchema {
    /// The operation name (e.g., `"read"`, `"invoke"`).
    pub name: String,
    /// Designation labels that must be attached at mint time for this
    /// operation. Excludes reserved labels (anchor, etc.), which are enforced
    /// through dedicated engine paths.
    #[serde(default)]
    pub required_designations: Vec<String>,
}

/// Top-level schema TOML wrapper. Only `[[targets]]` is consumed; other
/// top-level sections (e.g., `[tool]` from a harness manifest) are ignored.
#[derive(Debug, Deserialize)]
struct SchemaFile {
    #[serde(default)]
    targets: Vec<TargetSchema>,
}

/// Registry of target schemas, populated from one or more TOML sources.
///
/// Construct with [`SchemaRegistry::new`] for an empty registry, or via the
/// loading constructors. Use [`SchemaRegistry::add_file`] /
/// [`SchemaRegistry::add_toml`] to compose multiple sources; duplicate target
/// ids and reserved labels are caught at load time.
#[derive(Debug, Default, Clone)]
pub struct SchemaRegistry {
    targets: HashMap<String, TargetSchema>,
    /// Where each target was first declared, for error messages on duplicates.
    sources: HashMap<String, String>,
}

impl SchemaRegistry {
    /// Create an empty registry. The engine treats this as "no schemas declared,
    /// no required_designations enforcement."
    pub fn new() -> Self {
        Self::default()
    }

    /// Parse a TOML string and return a fresh registry.
    pub fn from_toml(content: &str) -> Result<Self, SchemaError> {
        let mut reg = Self::new();
        reg.add_toml_source(content, "<inline>")?;
        Ok(reg)
    }

    /// Load a single TOML file.
    pub fn from_file(path: &Path) -> Result<Self, SchemaError> {
        let mut reg = Self::new();
        reg.add_file(path)?;
        Ok(reg)
    }

    /// Load every `*.toml` file in a directory, non-recursively. Files are
    /// loaded in lexicographic order so the same directory produces the same
    /// registry across runs.
    pub fn from_dir(dir: &Path) -> Result<Self, SchemaError> {
        let mut reg = Self::new();
        let mut entries: Vec<PathBuf> = fs::read_dir(dir)
            .map_err(|source| SchemaError::Io {
                path: dir.to_path_buf(),
                source,
            })?
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| p.is_file() && p.extension() == Some(OsStr::new("toml")))
            .collect();
        entries.sort();
        for path in entries {
            reg.add_file(&path)?;
        }
        Ok(reg)
    }

    /// Add a TOML file to this registry. Errors on duplicate target ids or
    /// reserved labels.
    pub fn add_file(&mut self, path: &Path) -> Result<(), SchemaError> {
        let content = fs::read_to_string(path).map_err(|source| SchemaError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        self.add_toml_source(&content, &path.display().to_string())
    }

    /// Add a TOML string to this registry, attributing any errors to the
    /// `<inline>` source. Use [`SchemaRegistry::add_file`] when you have a path
    /// for better error messages.
    pub fn add_toml(&mut self, content: &str) -> Result<(), SchemaError> {
        self.add_toml_source(content, "<inline>")
    }

    /// Add a single target schema directly. Errors on duplicate id or reserved
    /// labels; useful for tests and programmatic construction.
    pub fn add_target(&mut self, schema: TargetSchema) -> Result<(), SchemaError> {
        self.add_target_with_source(schema, "<programmatic>")
    }

    /// Look up a target's schema.
    pub fn get(&self, target: &str) -> Option<&TargetSchema> {
        self.targets.get(target)
    }

    /// Look up the required designations for a `(target, operation)` pair.
    /// Returns `None` if either the target or the operation is not declared,
    /// which the engine treats as "no enforcement runs."
    pub fn required_designations(&self, target: &str, operation: &str) -> Option<&[String]> {
        self.targets
            .get(target)?
            .operations
            .iter()
            .find(|op| op.name == operation)
            .map(|op| op.required_designations.as_slice())
    }

    /// Iterate all declared target schemas.
    pub fn targets(&self) -> impl Iterator<Item = &TargetSchema> {
        self.targets.values()
    }

    /// Whether the registry has any targets.
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty()
    }

    fn add_toml_source(&mut self, content: &str, source: &str) -> Result<(), SchemaError> {
        let parsed: SchemaFile = toml::from_str(content).map_err(|err| SchemaError::Parse {
            source: PathBuf::from(source),
            err,
        })?;
        for target in parsed.targets {
            self.add_target_with_source(target, source)?;
        }
        Ok(())
    }

    fn add_target_with_source(
        &mut self,
        schema: TargetSchema,
        source: &str,
    ) -> Result<(), SchemaError> {
        validate_target(&schema)?;

        if let Some(first_source) = self.sources.get(&schema.id) {
            return Err(SchemaError::DuplicateTarget {
                id: schema.id,
                first: first_source.clone(),
                second: source.to_string(),
            });
        }

        self.sources.insert(schema.id.clone(), source.to_string());
        self.targets.insert(schema.id.clone(), schema);
        Ok(())
    }
}

fn validate_target(schema: &TargetSchema) -> Result<(), SchemaError> {
    let mut seen_ops: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for op in &schema.operations {
        if !seen_ops.insert(op.name.as_str()) {
            return Err(SchemaError::DuplicateOperation {
                target: schema.id.clone(),
                op: op.name.clone(),
            });
        }
        for label in &op.required_designations {
            if RESERVED_LABELS.contains(&label.as_str()) {
                return Err(SchemaError::ReservedLabel {
                    target: schema.id.clone(),
                    op: op.name.clone(),
                    label: label.clone(),
                });
            }
        }
    }
    Ok(())
}

/// Errors from schema parsing and validation.
#[derive(Error, Debug)]
pub enum SchemaError {
    #[error("failed to read schema file {}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to parse schema TOML at {}: {err}", source.display())]
    Parse {
        source: PathBuf,
        #[source]
        err: toml::de::Error,
    },

    #[error("duplicate target id '{id}' (first declared in {first}, redeclared in {second})")]
    DuplicateTarget {
        id: String,
        first: String,
        second: String,
    },

    #[error("target '{target}' declares operation '{op}' more than once")]
    DuplicateOperation { target: String, op: String },

    #[error(
        "target '{target}' operation '{op}' lists reserved label '{label}' in required_designations; reserved labels are handled by the engine through a dedicated path and cannot be declared here"
    )]
    ReservedLabel {
        target: String,
        op: String,
        label: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_registry_returns_none_for_lookups() {
        let reg = SchemaRegistry::new();
        assert!(reg.is_empty());
        assert!(reg.get("anything").is_none());
        assert!(reg.required_designations("a", "b").is_none());
    }

    #[test]
    fn parses_single_target_with_required_designations() {
        let toml = r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read",  required_designations = ["path_prefix"] },
  { name = "write", required_designations = ["path_prefix"] },
]
"#;
        let reg = SchemaRegistry::from_toml(toml).expect("parse");
        let req = reg
            .required_designations("filesystem:source", "read")
            .expect("op exists");
        assert_eq!(req, ["path_prefix"]);
        let req = reg
            .required_designations("filesystem:source", "write")
            .expect("op exists");
        assert_eq!(req, ["path_prefix"]);
    }

    #[test]
    fn missing_target_or_op_returns_none() {
        let toml = r#"
[[targets]]
id = "tool:web-search"
operations = [{ name = "invoke" }]
"#;
        let reg = SchemaRegistry::from_toml(toml).expect("parse");
        assert!(reg.required_designations("nope", "invoke").is_none());
        assert!(
            reg.required_designations("tool:web-search", "nope")
                .is_none()
        );
        let req = reg
            .required_designations("tool:web-search", "invoke")
            .expect("op exists");
        assert!(req.is_empty());
    }

    #[test]
    fn duplicate_target_in_same_file_errors() {
        let toml = r#"
[[targets]]
id = "filesystem:source"
operations = []

[[targets]]
id = "filesystem:source"
operations = []
"#;
        let err = SchemaRegistry::from_toml(toml).expect_err("must reject duplicate");
        match err {
            SchemaError::DuplicateTarget { id, .. } => assert_eq!(id, "filesystem:source"),
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn duplicate_operation_within_target_errors() {
        let toml = r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read" },
  { name = "read" },
]
"#;
        let err = SchemaRegistry::from_toml(toml).expect_err("must reject duplicate op");
        match err {
            SchemaError::DuplicateOperation { target, op } => {
                assert_eq!(target, "filesystem:source");
                assert_eq!(op, "read");
            }
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn anchor_in_required_designations_is_rejected() {
        let toml = r#"
[[targets]]
id = "filesystem:source"
operations = [
  { name = "read", required_designations = ["anchor", "path_prefix"] },
]
"#;
        let err = SchemaRegistry::from_toml(toml).expect_err("must reject anchor");
        match err {
            SchemaError::ReservedLabel { label, .. } => assert_eq!(label, "anchor"),
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn facet_in_required_designations_is_rejected() {
        let toml = r#"
[[targets]]
id = "tool:web-search"
operations = [
  { name = "invoke", required_designations = ["facet"] },
]
"#;
        let err = SchemaRegistry::from_toml(toml).expect_err("must reject facet");
        match err {
            SchemaError::ReservedLabel { label, .. } => assert_eq!(label, "facet"),
            other => panic!("wrong error variant: {other:?}"),
        }
    }

    #[test]
    fn unknown_top_level_sections_are_ignored() {
        // Bundled-with-manifest case: harness-specific [tool] and [input_schema]
        // sections coexist with [[targets]]. The schema loader consumes only
        // [[targets]].
        let toml = r#"
[tool]
name = "birthday_discord"
type = "subprocess"
command = "deno run birthday_discord.ts"

[input_schema]
type = "object"

[[targets]]
id = "tool:birthday-discord"
operations = [{ name = "invoke" }]
"#;
        let reg = SchemaRegistry::from_toml(toml).expect("parse");
        assert!(reg.get("tool:birthday-discord").is_some());
    }

    #[test]
    fn add_target_programmatic_and_duplicate_detection() {
        let mut reg = SchemaRegistry::new();
        reg.add_target(TargetSchema {
            id: "tool:web-search".to_string(),
            operations: vec![OperationSchema {
                name: "invoke".to_string(),
                required_designations: vec!["query".to_string()],
            }],
        })
        .expect("first add");

        let dup = reg.add_target(TargetSchema {
            id: "tool:web-search".to_string(),
            operations: vec![],
        });
        assert!(matches!(dup, Err(SchemaError::DuplicateTarget { .. })));
    }

    #[test]
    fn add_toml_composes_multiple_sources() {
        let mut reg = SchemaRegistry::new();
        reg.add_toml(
            r#"
[[targets]]
id = "filesystem:source"
operations = [{ name = "read", required_designations = ["path_prefix"] }]
"#,
        )
        .expect("first");
        reg.add_toml(
            r#"
[[targets]]
id = "tool:discord-dm"
operations = [{ name = "send", required_designations = ["user_id"] }]
"#,
        )
        .expect("second");

        assert_eq!(reg.targets().count(), 2);
        assert!(reg.get("filesystem:source").is_some());
        assert!(reg.get("tool:discord-dm").is_some());
    }
}
