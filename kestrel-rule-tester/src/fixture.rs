use kestrel_event::Event;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

/// A test fixture containing a sequence of events and an expected outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fixture {
    pub name: String,
    pub description: Option<String>,
    pub events: Vec<Event>,
    pub expected: ExpectedOutcome,
}

/// Expected outcome when running a rule against a fixture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectedOutcome {
    /// The rule should match at least one event in the fixture.
    ShouldMatch,
    /// The rule should not match any event in the fixture.
    ShouldNotMatch,
    /// The rule should generate at least one alert.
    ShouldAlert,
}

/// Errors that can occur when loading fixtures.
#[derive(Debug, Error)]
pub enum FixtureError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Unknown file format: {0}")]
    UnknownFormat(String),
}

/// Loads test fixtures from disk.
pub struct FixtureLoader;

impl FixtureLoader {
    /// Load a fixture from a JSON or YAML file.
    ///
    /// The file extension determines the format: `.json`, `.yaml`, or `.yml`.
    pub fn load(path: &Path) -> Result<Fixture, FixtureError> {
        let content = std::fs::read_to_string(path)?;

        let extension = path.extension().and_then(|e| e.to_str()).unwrap_or("");

        match extension {
            "json" => Ok(serde_json::from_str(&content)?),
            "yaml" | "yml" => Ok(serde_yaml::from_str(&content)?),
            _ => Err(FixtureError::UnknownFormat(extension.to_string())),
        }
    }

    /// Parse a fixture from a JSON string.
    pub fn from_json(content: &str) -> Result<Fixture, FixtureError> {
        Ok(serde_json::from_str(content)?)
    }

    /// Parse a fixture from a YAML string.
    pub fn from_yaml(content: &str) -> Result<Fixture, FixtureError> {
        Ok(serde_yaml::from_str(content)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_event::Event;

    fn sample_fixture() -> Fixture {
        Fixture {
            name: "process-exec-test".to_string(),
            description: Some("Test process execution".to_string()),
            events: vec![
                Event::builder()
                    .event_type(1)
                    .ts_mono(1000)
                    .ts_wall(1000)
                    .entity_key(42)
                    .build()
                    .unwrap(),
            ],
            expected: ExpectedOutcome::ShouldAlert,
        }
    }

    #[test]
    fn test_fixture_roundtrip_json() {
        let fixture = sample_fixture();
        let json = serde_json::to_string_pretty(&fixture).unwrap();
        let loaded = FixtureLoader::from_json(&json).unwrap();
        assert_eq!(loaded.name, fixture.name);
        assert_eq!(loaded.events.len(), 1);
        assert_eq!(loaded.expected, ExpectedOutcome::ShouldAlert);
    }

    #[test]
    fn test_fixture_roundtrip_yaml() {
        let fixture = sample_fixture();
        let yaml = serde_yaml::to_string(&fixture).unwrap();
        let loaded = FixtureLoader::from_yaml(&yaml).unwrap();
        assert_eq!(loaded.name, fixture.name);
        assert_eq!(loaded.events.len(), 1);
    }

    #[test]
    fn test_fixture_load_file() {
        let temp_dir = tempfile::tempdir().unwrap();
        let path = temp_dir.path().join("test.json");

        let fixture = sample_fixture();
        std::fs::write(&path, serde_json::to_string_pretty(&fixture).unwrap()).unwrap();

        let loaded = FixtureLoader::load(&path).unwrap();
        assert_eq!(loaded.name, "process-exec-test");
    }

    #[test]
    fn test_fixture_load_with_fields() {
        // Manually construct JSON with lowercase TypedValue keys to work around
        // the upstream serialize/deserialize case mismatch in kestrel-schema.
        let json = r#"{
            "name": "field-test",
            "description": null,
            "events": [
                {
                    "event_id": 0,
                    "event_type_id": 1,
                    "ts_mono_ns": 1000,
                    "ts_wall_ns": 1000,
                    "entity_key": 42,
                    "fields": [[1, {"string": "/bin/bash"}], [2, {"u64": 1234}]],
                    "source_id": null
                }
            ],
            "expected": "should_alert"
        }"#;

        let loaded = FixtureLoader::from_json(json).unwrap();
        assert_eq!(loaded.name, "field-test");
        assert_eq!(loaded.events.len(), 1);
        assert_eq!(loaded.events[0].fields.len(), 2);
        assert_eq!(
            loaded.events[0].get_field(1),
            Some(&kestrel_schema::TypedValue::String("/bin/bash".into()))
        );
        assert_eq!(loaded.events[0].get_field(2), Some(&kestrel_schema::TypedValue::U64(1234)));
    }
}
