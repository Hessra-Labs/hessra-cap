//! Example 2: recursive agent tool composition with context restrictions.
//!
//! Run with:
//! `cargo run --example example2_agent_tools -p hessra-cap`
//!
//! This models separate object-principals that all participate in one agent
//! request:
//!
//! - the root authority knows only the top-level objects under it
//! - `tool:filesystem` owns the `projects` namespace
//! - `myproject` owns its private file namespace
//!
//! Each layer applies the concrete designation it owns. The root authority
//! keeps the agent context and blocks exfiltration after the private file read.

use hessra_cap::{
    CListPolicy, CapabilityEngine, ContextToken, Designation, EngineError, ExposureLabel, ObjectId,
    Operation, SchemaRegistry, SessionConfig,
};
use hessra_cap_token::{CapabilityVerifier, HessraCapability};
use hessra_token_core::PublicKey;

const READ: &str = "read";
const INVOKE: &str = "invoke";

type ExampleResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ExampleResult<()> {
    let root = RootAuthority::new()?;
    let filesystem = FilesystemTool::new(root.public_key())?;
    let myproject = MyProject::new(filesystem.public_key())?;

    let agent = object("agent:assistant");
    let mut context = root.new_context(&agent)?;

    root.assert_can_invoke_web_fetch(&agent, &context)?;
    root.assert_can_invoke_slack_post(&agent, &context)?;

    let filesystem_invoke = root.mint_tool_invoke(&agent, "tool:filesystem", &context)?;
    filesystem.verify_invocation(&filesystem_invoke)?;

    let projects_read = root.mint_filesystem_to_projects(&context)?;
    let myproject_read = filesystem.mint_projects_to_myproject(&projects_read)?;
    let private_file_read = myproject.mint_private_file_read(&myproject_read)?;

    myproject.verify_private_file_read(&private_file_read)?;
    context = root.add_private_project_exposure(&context)?;

    root.assert_web_fetch_blocked(&agent, &context);
    root.assert_slack_post_blocked(&agent, &context);

    println!("example2_agent_tools passed");
    Ok(())
}

struct RootAuthority {
    engine: CapabilityEngine<CListPolicy>,
}

impl RootAuthority {
    fn new() -> ExampleResult<Self> {
        let policy = CListPolicy::from_toml(
            r#"
[[objects]]
id = "agent:assistant"
capabilities = [
    { target = "tool:filesystem", operations = ["invoke"] },
    { target = "tool:web-fetch", operations = ["invoke"] },
    { target = "tool:slack-post", operations = ["invoke"] },
]

[[objects]]
id = "tool:filesystem"
capabilities = [
    { target = "projects", operations = ["read"] },
]

[[exposure_rules]]
labels = ["project:private"]
blocks = ["tool:web-fetch", "tool:slack-post"]
"#,
        )?;

        Ok(Self {
            engine: CapabilityEngine::with_generated_keys(policy),
        })
    }

    fn public_key(&self) -> PublicKey {
        self.engine.public_key()
    }

    fn new_context(&self, agent: &ObjectId) -> ExampleResult<ContextToken> {
        Ok(self.engine.mint_context(agent, SessionConfig::default())?)
    }

    fn mint_tool_invoke(
        &self,
        agent: &ObjectId,
        tool: &str,
        context: &ContextToken,
    ) -> ExampleResult<String> {
        let result =
            self.engine
                .mint_capability(agent, &object(tool), &operation(INVOKE), Some(context))?;
        Ok(result.token)
    }

    fn mint_filesystem_to_projects(&self, context: &ContextToken) -> ExampleResult<String> {
        Ok(self
            .engine
            .mint_capability(
                &object("tool:filesystem"),
                &object("projects"),
                &operation(READ),
                Some(context),
            )?
            .token)
    }

    fn assert_can_invoke_web_fetch(
        &self,
        agent: &ObjectId,
        context: &ContextToken,
    ) -> ExampleResult<()> {
        let token = self.mint_tool_invoke(agent, "tool:web-fetch", context)?;
        self.engine
            .verify_capability(&token, &object("tool:web-fetch"), &operation(INVOKE))?;
        Ok(())
    }

    fn assert_can_invoke_slack_post(
        &self,
        agent: &ObjectId,
        context: &ContextToken,
    ) -> ExampleResult<()> {
        let token = self.mint_tool_invoke(agent, "tool:slack-post", context)?;
        self.engine
            .verify_capability(&token, &object("tool:slack-post"), &operation(INVOKE))?;
        Ok(())
    }

    fn add_private_project_exposure(&self, context: &ContextToken) -> ExampleResult<ContextToken> {
        Ok(self.engine.add_exposure_label(
            context,
            ExposureLabel::new("project:private"),
            &object("myproject:private_file"),
        )?)
    }

    fn assert_web_fetch_blocked(&self, agent: &ObjectId, context: &ContextToken) {
        assert!(matches!(
            self.engine.mint_capability(
                agent,
                &object("tool:web-fetch"),
                &operation(INVOKE),
                Some(context),
            ),
            Err(EngineError::ExposureBlocked { .. })
        ));
    }

    fn assert_slack_post_blocked(&self, agent: &ObjectId, context: &ContextToken) {
        assert!(matches!(
            self.engine.mint_capability(
                agent,
                &object("tool:slack-post"),
                &operation(INVOKE),
                Some(context),
            ),
            Err(EngineError::ExposureBlocked { .. })
        ));
    }
}

struct FilesystemTool {
    engine: CapabilityEngine<CListPolicy>,
    root_public_key: PublicKey,
}

impl FilesystemTool {
    fn new(root_public_key: PublicKey) -> ExampleResult<Self> {
        let policy = CListPolicy::from_toml(
            r#"
[[objects]]
id = "projects"
capabilities = [
    { target = "myproject", operations = ["read"] },
]
"#,
        )?;
        let schema = SchemaRegistry::from_toml(
            r#"
[[targets]]
id = "myproject"
operations = [
    { name = "read", required_designations = ["path_prefix"] },
]
"#,
        )?;

        Ok(Self {
            engine: CapabilityEngine::with_generated_keys(policy).with_schema(schema)?,
            root_public_key,
        })
    }

    fn public_key(&self) -> PublicKey {
        self.engine.public_key()
    }

    fn verify_invocation(&self, root_token: &str) -> Result<(), Box<dyn std::error::Error>> {
        CapabilityVerifier::new(
            root_token.to_string(),
            self.root_public_key,
            "tool:filesystem".to_string(),
            INVOKE.to_string(),
        )
        .verify()?;
        Ok(())
    }

    fn mint_projects_to_myproject(&self, root_projects_token: &str) -> ExampleResult<String> {
        let root_projects_token =
            HessraCapability::amend(root_projects_token, self.root_public_key)?
                .designation("path_prefix", "/projects")
                .attenuate()?;

        CapabilityVerifier::new(
            root_projects_token,
            self.root_public_key,
            "projects".to_string(),
            READ.to_string(),
        )
        .with_designation("path_prefix".to_string(), "/projects".to_string())
        .verify()?;

        let token = self
            .engine
            .mint_designated_capability(
                &object("projects"),
                &object("myproject"),
                &operation(READ),
                &[designation("path_prefix", "/projects/myproject")],
                None,
            )?
            .token;

        self.engine.verify_designated_capability(
            &token,
            &object("myproject"),
            &operation(READ),
            &[designation("path_prefix", "/projects/myproject")],
        )?;

        Ok(token)
    }
}

struct MyProject {
    engine: CapabilityEngine<CListPolicy>,
    filesystem_public_key: PublicKey,
}

impl MyProject {
    fn new(filesystem_public_key: PublicKey) -> ExampleResult<Self> {
        let policy = CListPolicy::from_toml(
            r#"
[[objects]]
id = "myproject"
capabilities = [
    { target = "private_file", operations = ["read"] },
]
"#,
        )?;
        let schema = SchemaRegistry::from_toml(
            r#"
[[targets]]
id = "private_file"
operations = [
    { name = "read", required_designations = ["path_prefix"] },
]
"#,
        )?;

        Ok(Self {
            engine: CapabilityEngine::with_generated_keys(policy).with_schema(schema)?,
            filesystem_public_key,
        })
    }

    fn mint_private_file_read(&self, filesystem_token: &str) -> ExampleResult<String> {
        CapabilityVerifier::new(
            filesystem_token.to_string(),
            self.filesystem_public_key,
            "myproject".to_string(),
            READ.to_string(),
        )
        .with_designation("path_prefix".to_string(), "/projects/myproject".to_string())
        .verify()?;

        let token = self
            .engine
            .mint_designated_capability(
                &object("myproject"),
                &object("private_file"),
                &operation(READ),
                &[designation(
                    "path_prefix",
                    "/projects/myproject/private_file",
                )],
                None,
            )?
            .token;

        Ok(token)
    }

    fn verify_private_file_read(&self, token: &str) -> ExampleResult<()> {
        self.engine.verify_designated_capability(
            token,
            &object("private_file"),
            &operation(READ),
            &[designation(
                "path_prefix",
                "/projects/myproject/private_file",
            )],
        )?;
        Ok(())
    }
}

fn object(id: &str) -> ObjectId {
    ObjectId::new(id)
}

fn operation(name: &str) -> Operation {
    Operation::new(name)
}

fn designation(label: &str, value: &str) -> Designation {
    Designation {
        label: label.into(),
        value: value.into(),
    }
}
