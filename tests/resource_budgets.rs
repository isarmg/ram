#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{Error, TestServer, server};
use hyper::StatusCode;
use reqwest::blocking::Response as BlockingResponse;
use rstest::rstest;
use serde_json::Value;
use std::fs;
use std::io::Cursor;
use std::path::Path;

fn write_entries(directory: &Path, prefix: &str, count: usize) -> Result<(), Error> {
    fs::create_dir_all(directory)?;
    for index in 0..count {
        fs::write(directory.join(format!("{prefix}-{index}")), b"x")?;
    }
    Ok(())
}

fn json_path_count(response: BlockingResponse) -> Result<usize, Error> {
    let value: Value = serde_json::from_str(&response.text()?)?;
    Ok(value["paths"]
        .as_array()
        .ok_or("directory response did not contain a paths array")?
        .len())
}

#[rstest]
fn directory_result_budget_has_exact_boundaries_and_head_skips_the_scan(
    #[with(&[
        "--max-directory-entries",
        "2",
        "--max-walk-entries",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "visible", count)?;
    }

    for (name, expected, truncated) in [("minus", 1, false), ("exact", 2, false), ("plus", 2, true)]
    {
        let response = reqwest::blocking::get(format!("{}{name}/?json", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            response.headers().get("x-ram-list-truncated").is_some(),
            truncated,
            "{name}"
        );
        assert_eq!(json_path_count(response)?, expected, "{name}");
    }

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?json", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(!head.headers().contains_key("x-ram-list-truncated"));
    assert!(!head.headers().contains_key("etag"));
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn search_result_budget_has_exact_boundaries_and_releases_its_worker(
    #[with(&[
        "--allow-search",
        "--max-search-results",
        "2",
        "--max-walk-entries",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "needle", count)?;
    }

    for (name, expected, truncated) in [("minus", 1, false), ("exact", 2, false), ("plus", 2, true)]
    {
        let response = reqwest::blocking::get(format!("{}{name}/?q=needle&json", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(
            response.headers().get("x-ram-list-truncated").is_some(),
            truncated,
            "{name}"
        );
        assert_eq!(json_path_count(response)?, expected, "{name}");
    }

    // 完成遍历必须归还唯一昂贵任务 permit。 / A completed traversal must return the sole expensive-task permit.
    let recovered = reqwest::blocking::get(format!("{}minus/?q=needle&json", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    assert_eq!(json_path_count(recovered)?, 1);

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?q=needle&json", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(!head.headers().contains_key("x-ram-list-truncated"));
    assert!(!head.headers().contains_key("etag"));
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn walk_entry_budget_rejects_only_n_plus_one_and_then_releases_the_permit(
    #[with(&[
        "--allow-search",
        "--max-walk-entries",
        "2",
        "--max-walk-depth",
        "8",
        "--max-search-results",
        "100",
        "--max-expensive-tasks",
        "1",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, count) in [("minus", 1), ("exact", 2), ("plus", 3)] {
        write_entries(&server.path().join(name), "match", count)?;
    }

    for (name, expected) in [
        ("minus", StatusCode::OK),
        ("exact", StatusCode::OK),
        ("plus", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = reqwest::blocking::get(format!("{}{name}/?q=match&json", server.url()))?;
        assert_eq!(response.status(), expected, "{name}");
        assert!(!response.headers().contains_key("retry-after"), "{name}");
    }

    let recovered = reqwest::blocking::get(format!("{}exact/?q=match&json", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    Ok(())
}

#[rstest]
fn walk_depth_budget_has_n_minus_one_n_and_n_plus_one(
    #[with(&[
        "--allow-search",
        "--max-walk-entries",
        "100",
        "--max-walk-depth",
        "2",
        "--max-search-results",
        "100",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for path in ["minus/d1/match", "exact/d1/d2/match", "plus/d1/d2/d3/match"] {
        let path = server.path().join(path);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, b"x")?;
    }

    for (name, expected) in [
        ("minus", StatusCode::OK),
        ("exact", StatusCode::OK),
        ("plus", StatusCode::UNPROCESSABLE_ENTITY),
    ] {
        let response = reqwest::blocking::get(format!("{}{name}/?q=match&json", server.url()))?;
        assert_eq!(response.status(), expected, "{name}");
        assert!(!response.headers().contains_key("retry-after"), "{name}");
    }
    Ok(())
}

#[rstest]
fn archive_uncompressed_budget_has_exact_boundaries_and_an_early_error_status(
    #[with(&[
        "--allow-archive",
        "--compress",
        "none",
        "--max-archive-size",
        "8",
        "--max-walk-entries",
        "100",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    for (name, size) in [("minus", 7), ("exact", 8), ("plus", 9)] {
        fs::create_dir(server.path().join(name))?;
        fs::write(
            server.path().join(name).join("payload.bin"),
            vec![b'x'; size],
        )?;
    }

    for name in ["minus", "exact"] {
        let response = reqwest::blocking::get(format!("{}{name}/?zip", server.url()))?;
        assert_eq!(response.status(), StatusCode::OK, "{name}");
        assert_eq!(response.headers()["content-type"], "application/zip");
        let archive = response.bytes()?;
        let mut archive = zip::ZipArchive::new(Cursor::new(archive))?;
        assert_eq!(archive.len(), 2, "{name}");
        assert_eq!(
            archive.by_name("archive/payload.bin")?.size(),
            if name == "minus" { 7 } else { 8 }
        );
    }

    // 生产者提交响应头前必须验证稳定元数据。先返回 200 再重置截断 ZIP 流，对 HTTP/1 或 H2
    // 客户端都不是可处理的超预算响应。
    // The producer must validate stable metadata before committing headers; a 200 followed by a
    // reset of a truncated ZIP stream is not an actionable over-budget response for HTTP/1 or H2 clients.
    let response = reqwest::blocking::get(format!("{}plus/?zip", server.url()))?;
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    assert!(!response.headers().contains_key("content-disposition"));
    assert_eq!(response.text()?, "Unprocessable Entity");

    let head = reqwest::blocking::Client::new()
        .head(format!("{}plus/?zip", server.url()))
        .send()?;
    assert_eq!(head.status(), StatusCode::OK);
    assert!(head.bytes()?.is_empty());

    let recovered = reqwest::blocking::get(format!("{}exact/?zip", server.url()))?;
    assert_eq!(recovered.status(), StatusCode::OK);
    let _ = zip::ZipArchive::new(Cursor::new(recovered.bytes()?))?;
    Ok(())
}
