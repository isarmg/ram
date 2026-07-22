use super::{NodeKind, RootFs};
use crate::identity::ServedPathIdentity;
use anyhow::Result;
use assert_fs::TempDir;
use rustix::fs::ResolveFlags;
use std::io::Read;
use std::path::Path;

#[test]
fn verified_root_uses_pinned_directory_after_namespace_replacement() -> Result<()> {
    let temp = TempDir::new()?;
    let served = temp.path().join("served");
    let moved = temp.path().join("validated-but-moved");
    std::fs::create_dir(&served)?;
    std::fs::write(served.join("trusted.txt"), b"trusted")?;
    let expected = ServedPathIdentity::capture(&served, false)?;

    std::fs::rename(&served, &moved)?;
    std::fs::create_dir(&served)?;
    std::fs::write(served.join("decoy.txt"), b"decoy")?;
    let root = RootFs::from_verified_identity(&expected, false, false)?;
    let mut trusted = root.open_raw(Path::new("trusted.txt"), NodeKind::File)?;
    let mut body = String::new();
    trusted.read_to_string(&mut body)?;
    assert_eq!(body, "trusted");
    assert!(
        root.open_raw(Path::new("decoy.txt"), NodeKind::File)
            .is_err()
    );
    Ok(())
}

#[test]
fn verified_single_file_uses_pinned_inode_after_namespace_replacement() -> Result<()> {
    let temp = TempDir::new()?;
    let served = temp.path().join("served.txt");
    std::fs::write(&served, b"validated")?;
    let expected = ServedPathIdentity::capture(&served, true)?;

    std::fs::remove_file(&served)?;
    std::fs::write(&served, b"replacement")?;
    let root = RootFs::from_verified_identity(&expected, false, false)?;
    let mut opened = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
    let mut body = String::new();
    opened.read_to_string(&mut body)?;
    assert_eq!(body, "validated");
    Ok(())
}

#[test]
fn initialized_single_file_keeps_serving_only_the_pinned_inode() -> Result<()> {
    let temp = TempDir::new()?;
    let served = temp.path().join("served.txt");
    let moved = temp.path().join("old.txt");
    std::fs::write(&served, b"validated inode")?;
    let expected = ServedPathIdentity::capture(&served, true)?;
    let root = RootFs::from_verified_identity(&expected, false, false)?;

    std::fs::rename(&served, &moved)?;
    std::fs::remove_file(&moved)?;
    std::fs::write(&served, b"replacement secret")?;

    let mut first = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
    let mut second = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
    let mut first_body = String::new();
    let mut second_body = String::new();
    first.read_to_string(&mut first_body)?;
    second.read_to_string(&mut second_body)?;
    assert_eq!(first_body, "validated inode");
    assert_eq!(second_body, "validated inode");
    assert_eq!(
        root.real_relative_verified(&first)?,
        Path::new("served.txt")
    );
    Ok(())
}

#[test]
fn single_file_readiness_tracks_the_configured_namespace_identity() -> Result<()> {
    let temp = TempDir::new()?;
    let parent = temp.path().join("configured-parent");
    let moved_parent = temp.path().join("startup-parent");
    std::fs::create_dir(&parent)?;
    let served = parent.join("served.txt");
    std::fs::write(&served, b"startup inode")?;
    let expected = ServedPathIdentity::capture(&served, true)?;
    let root = RootFs::from_verified_identity(&expected, false, false)?;
    expected.verify_namespace()?;

    std::fs::rename(&parent, &moved_parent)?;
    std::fs::create_dir(&parent)?;
    std::fs::write(&served, b"replacement inode")?;
    assert!(
        expected.verify_namespace().is_err(),
        "replacement of an ancestor must make readiness fail"
    );

    let mut opened = root.open_raw(Path::new("served.txt"), NodeKind::File)?;
    let mut body = String::new();
    opened.read_to_string(&mut body)?;
    assert_eq!(
        body, "startup inode",
        "read requests must remain pinned to the startup capability"
    );
    Ok(())
}

#[test]
fn no_xdev_policy_is_default_and_compatibility_must_be_explicit() -> Result<()> {
    let temp = TempDir::new()?;
    let expected = ServedPathIdentity::capture(temp.path(), false)?;
    let strict = RootFs::from_verified_identity(&expected, false, false)?;
    assert!(strict.resolve_flags().contains(ResolveFlags::NO_XDEV));

    let compatibility = RootFs::from_verified_identity(&expected, false, true)?;
    assert!(
        !compatibility
            .resolve_flags()
            .contains(ResolveFlags::NO_XDEV)
    );
    Ok(())
}
