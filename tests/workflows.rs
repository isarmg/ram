use serde_yaml_ng::{Mapping, Value};
use std::error::Error;
use std::fs;
use std::path::Path;

fn mapping<'a>(value: &'a Value, location: &str) -> Result<&'a Mapping, Box<dyn Error>> {
    value
        .as_mapping()
        .ok_or_else(|| format!("{location} must be a YAML mapping").into())
}

#[test]
fn every_github_actions_workflow_is_valid_nonempty_yaml() -> Result<(), Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut workflow_count = 0usize;
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if !matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) {
            continue;
        }
        workflow_count += 1;
        let source = fs::read_to_string(&path)?;
        let document: Value = serde_yaml_ng::from_str(&source)
            .map_err(|error| format!("{} is not valid YAML: {error}", path.display()))?;
        let root = mapping(&document, &path.display().to_string())?;
        for required in ["name", "on", "jobs"] {
            assert!(
                root.contains_key(Value::String(required.to_owned())),
                "{} has no top-level {required:?} key",
                path.display()
            );
        }
        let jobs = mapping(
            root.get(Value::String("jobs".to_owned()))
                .expect("jobs presence was checked"),
            "workflow jobs",
        )?;
        assert!(!jobs.is_empty(), "{} contains no jobs", path.display());
    }
    assert!(
        workflow_count >= 3,
        "expected CI, release, and performance workflows"
    );
    Ok(())
}
