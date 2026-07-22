//! 可移植原子替换元数据验收框架。
//! Portable atomic-replacement metadata acceptance harness.
//!
//! 普通测试运行覆盖当前临时文件系统；CI 可在显式 ext4/XFS 挂载上运行相同用例而无需改代码：
//! The ordinary run exercises the current temporary filesystem. CI can run identical cases on ext4
//! and XFS mounts without changing test code:
//!
//! `TMPDIR=/mounted/ext4 RAM_METADATA_EXPECT_FS=ext2/ext3 cargo test --test metadata`
//!
//! `TMPDIR=/mounted/xfs RAM_METADATA_EXPECT_FS=xfs cargo test --test metadata`

#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, TestServer, server};
use rstest::rstest;
use rustix::fs::XattrFlags;
use rustix::io::Errno;
use std::fs::{FileTimes, OpenOptions};
use std::os::unix::fs::{MetadataExt, PermissionsExt, chown};
use std::path::Path;
use std::process::Command;
use std::time::{Duration, SystemTime};

const TEST_XATTR: &str = "user.ram_metadata_policy";
const ACCESS_ACL_XATTR: &str = "system.posix_acl_access";
const DEFAULT_ACL_XATTR: &str = "system.posix_acl_default";
const ACL_XATTR_VERSION: u32 = 0x0002;
const ACL_USER_OBJ: u16 = 0x01;
const ACL_USER: u16 = 0x02;
const ACL_GROUP_OBJ: u16 = 0x04;
const ACL_MASK: u16 = 0x10;
const ACL_OTHER: u16 = 0x20;
const ACL_UNDEFINED_ID: u32 = u32::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AclEntry {
    tag: u16,
    permissions: u16,
    id: u32,
}

fn filesystem_matrix_label(path: &Path) -> Result<String, Error> {
    let output = match Command::new("stat")
        .args(["-f", "-c", "%T"])
        .arg(path)
        .output()
    {
        Ok(output) if output.status.success() => output,
        Ok(output) => {
            eprintln!(
                "SKIP ext4/xfs matrix label: stat failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
            return Ok("unknown".to_string());
        }
        Err(error) => {
            eprintln!("SKIP ext4/xfs matrix label: stat is unavailable: {error}");
            return Ok("unknown".to_string());
        }
    };
    let actual = String::from_utf8(output.stdout)?.trim().to_string();
    if let Ok(expected) = std::env::var("RAM_METADATA_EXPECT_FS") {
        assert_eq!(
            actual, expected,
            "metadata acceptance ran on an unexpected filesystem"
        );
    } else if !matches!(actual.as_str(), "ext2/ext3" | "ext2/ext3/ext4" | "xfs") {
        eprintln!(
            "SKIP ext4/xfs-specific matrix assertion on {actual}; the portable metadata policy assertions still ran. Set RAM_METADATA_EXPECT_FS in ext4/xfs CI jobs."
        );
    }
    Ok(actual)
}

fn acl_entry(tag: u16, permissions: u16, id: u32) -> AclEntry {
    AclEntry {
        tag,
        permissions,
        id,
    }
}

fn encode_posix_acl(entries: &[AclEntry]) -> Vec<u8> {
    let mut encoded = Vec::with_capacity(4 + entries.len() * 8);
    encoded.extend_from_slice(&ACL_XATTR_VERSION.to_le_bytes());
    for entry in entries {
        encoded.extend_from_slice(&entry.tag.to_le_bytes());
        encoded.extend_from_slice(&entry.permissions.to_le_bytes());
        encoded.extend_from_slice(&entry.id.to_le_bytes());
    }
    encoded
}

fn decode_posix_acl(encoded: &[u8]) -> Result<Vec<AclEntry>, Error> {
    if encoded.len() < 4 || !(encoded.len() - 4).is_multiple_of(8) {
        return Err(format!(
            "kernel returned malformed POSIX ACL xattr length {}",
            encoded.len()
        )
        .into());
    }
    let version = u32::from_le_bytes(encoded[..4].try_into()?);
    if version != ACL_XATTR_VERSION {
        return Err(format!("kernel returned POSIX ACL xattr version {version:#x}").into());
    }
    encoded[4..]
        .chunks_exact(8)
        .map(|entry| {
            Ok(AclEntry {
                tag: u16::from_le_bytes(entry[..2].try_into()?),
                permissions: u16::from_le_bytes(entry[2..4].try_into()?),
                id: u32::from_le_bytes(entry[4..8].try_into()?),
            })
        })
        .collect()
}

fn named_acl(uid: u32, named_permissions: u16, mask_permissions: u16) -> Vec<u8> {
    encode_posix_acl(&[
        acl_entry(ACL_USER_OBJ, 0o7, ACL_UNDEFINED_ID),
        acl_entry(ACL_USER, named_permissions, uid),
        acl_entry(ACL_GROUP_OBJ, 0o5, ACL_UNDEFINED_ID),
        acl_entry(ACL_MASK, mask_permissions, ACL_UNDEFINED_ID),
        acl_entry(ACL_OTHER, 0o4, ACL_UNDEFINED_ID),
    ])
}

fn set_raw_acl(path: &Path, name: &str, value: &[u8], capability: &str) -> Result<bool, Error> {
    match rustix::fs::setxattr(path, name, value, XattrFlags::empty()) {
        Ok(()) => Ok(true),
        Err(error)
            if matches!(
                error,
                Errno::NOTSUP | Errno::PERM | Errno::ACCESS | Errno::INVAL
            ) =>
        {
            eprintln!(
                "SKIP {capability} POSIX ACL subcase: kernel/filesystem rejected {name}: {error}"
            );
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn read_raw_acl(path: &Path, name: &str) -> Result<Option<Vec<AclEntry>>, Error> {
    let mut encoded = [0_u8; 512];
    match rustix::fs::getxattr(path, name, &mut encoded[..]) {
        Ok(length) => Ok(Some(decode_posix_acl(&encoded[..length])?)),
        Err(Errno::NODATA) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

fn set_test_xattr(path: &Path) -> Result<bool, Error> {
    match rustix::fs::setxattr(path, TEST_XATTR, b"old inode value", XattrFlags::empty()) {
        Ok(()) => Ok(true),
        Err(error) if matches!(error, Errno::NOTSUP | Errno::PERM | Errno::ACCESS) => {
            eprintln!("SKIP user-xattr subcase: filesystem denied user xattrs: {error}");
            Ok(false)
        }
        Err(error) => Err(error.into()),
    }
}

fn assert_test_xattr_absent(path: &Path) -> Result<(), Error> {
    let mut value = [0_u8; 128];
    match rustix::fs::getxattr(path, TEST_XATTR, &mut value[..]) {
        Err(Errno::NODATA) => Ok(()),
        Err(error) if error == Errno::NOTSUP => {
            Err(format!("xattr support disappeared between set and replacement: {error}").into())
        }
        Err(error) => Err(error.into()),
        Ok(length) => Err(format!(
            "replacement unexpectedly copied {TEST_XATTR}={:?}",
            &value[..length]
        )
        .into()),
    }
}

#[rstest]
fn replacement_uses_new_inode_metadata_and_drops_unapproved_metadata(
    #[with(&[
        "-A",
        "--upload-file-mode",
        "0640",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let fs_type = filesystem_matrix_label(server.path())?;
    let target = server.path().join("metadata-policy.bin");
    let alias = server.path().join("metadata-policy-hardlink.bin");
    std::fs::write(&target, b"old representation")?;

    let euid = rustix::process::geteuid().as_raw();
    let old_uid_changed = if euid == 0 {
        match chown(&target, Some(65_534), None) {
            Ok(()) => true,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code)
                        if code == Errno::INVAL.raw_os_error()
                            || code == Errno::PERM.raw_os_error()
                ) =>
            {
                eprintln!(
                    "SKIP distinct-old-owner subcase: user namespace cannot chown to uid 65534"
                );
                false
            }
            Err(error) => return Err(error.into()),
        }
    } else {
        eprintln!("SKIP distinct-old-owner subcase: test process is not root");
        false
    };
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o6754))?;
    let old_time = SystemTime::now() - Duration::from_secs(2 * 60 * 60);
    OpenOptions::new()
        .write(true)
        .open(&target)?
        .set_times(FileTimes::new().set_modified(old_time))?;

    let xattr_supported = set_test_xattr(&target)?;
    let acl_uid = if euid == 65_534 { 65_533 } else { 65_534 };
    let access_acl_supported = set_raw_acl(
        &target,
        ACCESS_ACL_XATTR,
        &named_acl(acl_uid, 0o4, 0o5),
        "access",
    )?;
    std::fs::hard_link(&target, &alias)?;
    let old = std::fs::metadata(&target)?;
    assert_eq!(old.nlink(), 2);
    if old_uid_changed {
        assert_eq!(old.uid(), 65_534);
    }

    let response = fetch!(b"PUT", format!("{}metadata-policy.bin", server.url()))
        .body(b"new representation".to_vec())
        .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);

    let replaced = std::fs::metadata(&target)?;
    let parent = std::fs::metadata(server.path())?;
    let expected_gid = if parent.mode() & 0o2000 != 0 {
        parent.gid()
    } else {
        rustix::process::getegid().as_raw()
    };
    assert_ne!(replaced.ino(), old.ino(), "PUT must publish a new inode");
    assert_eq!(replaced.nlink(), 1);
    assert_eq!(
        replaced.uid(),
        euid,
        "owner comes from the service identity"
    );
    assert_eq!(
        replaced.gid(),
        expected_gid,
        "group comes from normal create/setgid-directory policy"
    );
    assert_eq!(replaced.mode() & 0o7777, 0o754);
    assert!(
        (replaced.mtime(), replaced.mtime_nsec()) > (old.mtime(), old.mtime_nsec()),
        "replacement must not preserve the old representation mtime"
    );
    assert_eq!(std::fs::read(&target)?, b"new representation");
    assert_eq!(std::fs::read(&alias)?, b"old representation");

    if xattr_supported {
        assert_test_xattr_absent(&target)?;
    }
    if access_acl_supported {
        let acl = read_raw_acl(&target, ACCESS_ACL_XATTR)?;
        assert!(
            acl.as_ref().is_none_or(|entries| !entries
                .iter()
                .any(|entry| entry.tag == ACL_USER && entry.id == acl_uid)),
            "replacement copied an old inode ACL entry: {acl:?}"
        );
    }
    eprintln!("metadata replacement policy verified on filesystem type {fs_type}");
    Ok(())
}

#[rstest]
fn new_inode_inherits_parent_default_acl_then_applies_configured_mode(
    #[with(&[
        "-A",
        "--upload-file-mode",
        "0640",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let fs_type = filesystem_matrix_label(server.path())?;
    let euid = rustix::process::geteuid().as_raw();
    let acl_uid = if euid == 65_534 { 65_533 } else { 65_534 };
    if !set_raw_acl(
        server.path(),
        DEFAULT_ACL_XATTR,
        &named_acl(acl_uid, 0o7, 0o7),
        "default",
    )? {
        return Ok(());
    }

    let response = fetch!(
        b"PUT",
        format!("{}default-acl-inheritance.bin", server.url())
    )
    .body(b"new file".to_vec())
    .send()?;
    assert_eq!(response.status(), reqwest::StatusCode::CREATED);

    let path = server.path().join("default-acl-inheritance.bin");
    let metadata = std::fs::metadata(&path)?;
    assert_eq!(metadata.mode() & 0o7777, 0o640);
    let acl = read_raw_acl(&path, ACCESS_ACL_XATTR)?
        .ok_or("new inode has no access ACL after successful default ACL setup")?;
    assert!(
        acl.iter().any(|entry| {
            entry.tag == ACL_USER && entry.id == acl_uid && entry.permissions == 0o7
        }),
        "new inode did not inherit the parent's named default ACL: {acl:?}"
    );
    assert!(
        acl.iter().any(|entry| {
            entry.tag == ACL_MASK && entry.id == ACL_UNDEFINED_ID && entry.permissions == 0o4
        }),
        "fchmod did not reconcile the inherited ACL mask with mode 0640: {acl:?}"
    );
    eprintln!("default ACL inheritance verified on filesystem type {fs_type}");
    Ok(())
}
