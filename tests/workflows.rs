use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeSet;
use std::error::Error;
use std::fs;
use std::path::Path;

fn mapping<'a>(value: &'a Value, location: &str) -> Result<&'a Mapping, Box<dyn Error>> {
    value
        .as_mapping()
        .ok_or_else(|| format!("{location} must be a YAML mapping").into())
}

fn workflow_source(name: &str) -> Result<String, Box<dyn Error>> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows")
        .join(name);
    Ok(fs::read_to_string(path)?)
}

#[test]
fn repository_has_only_the_supported_workflows() -> Result<(), Box<dyn Error>> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut workflows = BTreeSet::new();
    for entry in fs::read_dir(&directory)? {
        let path = entry?.path();
        if matches!(
            path.extension().and_then(|value| value.to_str()),
            Some("yml" | "yaml")
        ) {
            workflows.insert(
                path.file_name()
                    .and_then(|value| value.to_str())
                    .ok_or("workflow filename is not UTF-8")?
                    .to_owned(),
            );
        }
    }
    assert_eq!(
        workflows,
        BTreeSet::from([
            "browser-compat.yaml".to_owned(),
            "ci.yaml".to_owned(),
            "fuzz.yaml".to_owned(),
            "release.yaml".to_owned(),
        ])
    );
    Ok(())
}

#[test]
fn every_workflow_is_valid_nonempty_yaml() -> Result<(), Box<dyn Error>> {
    for name in [
        "browser-compat.yaml",
        "ci.yaml",
        "fuzz.yaml",
        "release.yaml",
    ] {
        let source = workflow_source(name)?;
        let document: Value = serde_yaml_ng::from_str(&source)
            .map_err(|error| format!("{name} is not valid YAML: {error}"))?;
        let root = mapping(&document, name)?;
        for required in ["name", "on", "jobs"] {
            assert!(
                root.contains_key(Value::String(required.to_owned())),
                "{name} has no top-level {required:?} key"
            );
        }
        let jobs = mapping(
            root.get(Value::String("jobs".to_owned()))
                .expect("jobs presence was checked"),
            "workflow jobs",
        )?;
        assert!(!jobs.is_empty(), "{name} contains no jobs");
    }
    Ok(())
}

#[test]
fn ci_matches_the_personal_linux_browser_scope() -> Result<(), Box<dyn Error>> {
    let source = workflow_source("ci.yaml")?;
    for required in [
        "cargo fmt --all --check",
        "cargo clippy --all-targets --all-features --locked -- -D warnings",
        "cargo test --all-features --locked",
        "npm ci --ignore-scripts",
        "npm run check",
        "playwright install --with-deps chromium",
        "test:e2e -- --project=chromium",
        "cargo audit --deny warnings",
        "cargo deny --locked check",
        "scripts/check-license-policy.py",
        "mkfs.ext4",
        "RAM_METADATA_EXPECT_FS=ext2/ext3",
        "cargo test --all-features --test metadata --locked",
    ] {
        assert!(source.contains(required), "CI is missing {required:?}");
    }
    for removed in [
        "aarch64",
        "xfs",
        "firefox",
        "webkit",
        "cargo llvm-cov",
        "privileged-unix",
    ] {
        assert!(
            !source.to_ascii_lowercase().contains(removed),
            "CI still contains removed scope {removed:?}"
        );
    }
    Ok(())
}

#[test]
fn secondary_browsers_run_only_manually_or_monthly() -> Result<(), Box<dyn Error>> {
    let source = workflow_source("browser-compat.yaml")?;
    for required in [
        "workflow_dispatch:",
        "cron: \"41 4 15 * *\"",
        "- firefox",
        "- webkit",
        "playwright install --with-deps",
        "test:e2e -- --project=",
    ] {
        assert!(
            source.contains(required),
            "browser compatibility workflow is missing {required:?}"
        );
    }
    assert!(!source.contains("pull_request:"));
    assert!(!source.contains("\n  push:"));
    Ok(())
}

#[test]
fn fuzz_runs_only_manually_or_monthly() -> Result<(), Box<dyn Error>> {
    let source = workflow_source("fuzz.yaml")?;
    assert!(source.contains("workflow_dispatch:"));
    assert!(source.contains("cron: \"23 3 1 * *\""));
    assert!(!source.contains("pull_request:"));
    assert!(!source.contains("\n  push:"));
    assert!(!source.contains("webdav_xml"));
    Ok(())
}

#[test]
fn release_is_a_single_public_x86_64_github_release() -> Result<(), Box<dyn Error>> {
    let source = workflow_source("release.yaml")?;
    for required in [
        "^v[0-9]+\\.[0-9]+\\.[0-9]+$",
        "cargo build --release --locked",
        "x86_64-unknown-linux-gnu",
        "cp LICENSE README.md config.example.yaml",
        "sha256sum",
        "softprops/action-gh-release@",
    ] {
        assert!(source.contains(required), "release is missing {required:?}");
    }
    for removed in [
        "aarch64",
        "cargo publish",
        "sbom",
        "attest",
        "draft: true",
        "finalize",
        "signature",
    ] {
        assert!(
            !source.to_ascii_lowercase().contains(removed),
            "release still contains removed scope {removed:?}"
        );
    }
    Ok(())
}
