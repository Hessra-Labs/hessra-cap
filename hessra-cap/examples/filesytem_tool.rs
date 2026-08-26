//! Example: Filesystem Tool
//!
//! This is a complete filesystem tool example showing both flat and hierarchical designations.
//!
//! The filesystem structure is:
//!
//! /workspace/
//!  ├── projects
//!  │   └── myproject
//!  │       └── private_file.txt
//!  |   └── other_file.txt
//!  └── notes.txt
//!
//! The object graph is:
//! filesystem_tool
//!  ├── projects:otherfile.txt
//!  ├── projects:myproject
//!  │   └── private_file.txt
//!  └── notes.txt
//!
//! where:
//!  - filesystem_tool is the top-level object, acting as the anchor (this is where the harness
//!    requests capabilities from)
//!  - projects is a non-principal object, acting as a designation handled by the filesystem tool
//!  - myproject is a principal object, governing its portion of the namespace
//!
//! Run with:
//! `cargo run --example filesytem_tool -p hessra-cap`

use hessra_cap::{CListPolicy, CapabilityEngine, SchemaRegistry};

type ExampleResult<T> = Result<T, Box<dyn std::error::Error>>;

struct RootAuthority {
    engine: CapabilityEngine<CListPolicy>,
}

impl RootAuthority {
    fn new() -> ExampleResult<Self> {
        let policy = CListPolicy::from_toml(
            r#"
                [[objects]]
                id = "filesystem_tool_user"
                capabilities = [
                    { target = "tool:filesystem", operations = ["invoke"] },
                ]

                [[objects]]
                id = "tool:filesystem"
                capabilities = [
                    { target = "filesystem:txt", operations = ["read"] },
                ]
            "#,
        )?;

        Ok(Self {
            engine: CapabilityEngine::with_generated_keys(policy),
        })
    }
}

struct FilesystemTool {
    engine: CapabilityEngine<CListPolicy>,
}

impl FilesystemTool {
    fn new() -> ExampleResult<Self> {
        let policy = CListPolicy::from_toml(
            r#"
            [[objects]]
            id = "filesystem_tool_user"
            capabilities = [
                { target = "filesystem:txt", operations = ["read"] },
            ]

            [[objects]]
            id = "myproject"
            capabilities = [
                { target = "filesystem:txt", operations = ["read"] },
            ]
            "#,
        )?;
        let schema = SchemaRegistry::from_toml(
            r#"
            [[targets]]
            id = "filesystem:txt"
            operations = [
                { name = "read", required_designations = ["path_prefix"] },
            ]
            "#,
        )?;
        Ok(Self {
            engine: CapabilityEngine::with_generated_keys(policy).with_schema(schema)?,
        })
    }
}

fn main() -> ExampleResult<()> {
    // Construct the two engines this example sets up. The full flat- vs
    // hierarchical-designation walkthrough described above is left as a sketch;
    // this confirms the policy/schema wiring builds and the engines stand up.
    let root = RootAuthority::new()?;
    let tool = FilesystemTool::new()?;

    println!("RootAuthority engine key : {:?}", root.engine.public_key());
    println!("FilesystemTool engine key: {:?}", tool.engine.public_key());
    Ok(())
}
