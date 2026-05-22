//! Kestrel Rule Tester
//!
//! A sandbox and deterministic validation framework for Kestrel detection rules.
//! Provides rule validation, fixture-based testing, and sandboxed execution.

pub mod fixture;
pub mod sandbox;
pub mod validator;

pub use fixture::*;
pub use sandbox::*;
pub use validator::*;

use kestrel_rules::{Rule, RuleDefinition};
use std::io;

/// Write a rule as a directory package into a temporary directory.
///
/// This creates the proper `manifest.json` and definition files expected by
/// [`kestrel_rules::RuleManager`].
pub(crate) fn write_rule_package(temp_dir: &std::path::Path, rule: &Rule) -> io::Result<()> {
    let package_dir = temp_dir.join("rule_pkg");
    std::fs::create_dir(&package_dir)?;

    let manifest = kestrel_schema::RuleManifest {
        format_version: "1.0".to_string(),
        metadata: kestrel_schema::RuleMetadata {
            rule_id: rule.metadata.id.clone(),
            rule_name: rule.metadata.name.clone(),
            rule_version: rule.metadata.version.clone(),
            author: rule.metadata.author.clone(),
            description: rule.metadata.description.clone(),
            tags: rule.metadata.tags.clone(),
            severity: rule.metadata.severity.to_string(),
            schema_version: "1.0".to_string(),
        },
        capabilities: kestrel_schema::RuleCapabilities::default(),
    };

    let manifest_json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(package_dir.join("manifest.json"), manifest_json)?;

    match &rule.definition {
        RuleDefinition::Eql(eql) => {
            std::fs::write(package_dir.join("rule.eql"), eql)?;
        },
        RuleDefinition::Lua(lua) => {
            std::fs::write(package_dir.join("predicate.lua"), lua)?;
        },
        RuleDefinition::Wasm(wasm) => {
            std::fs::write(package_dir.join("rule.wasm"), wasm)?;
        },
    }

    Ok(())
}
