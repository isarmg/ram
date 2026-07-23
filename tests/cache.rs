#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use chrono::{DateTime, Duration};
use fixtures::{Error, TestServer, server};
use reqwest::StatusCode;
use reqwest::header::{
    CACHE_CONTROL, ETAG, HeaderMap, HeaderName, HeaderValue, IF_MATCH, IF_MODIFIED_SINCE,
    IF_NONE_MATCH, IF_RANGE, IF_UNMODIFIED_SINCE, LAST_MODIFIED, VARY,
};
use rstest::rstest;
use std::fs::{FileTimes, OpenOptions};
use std::os::unix::fs::MetadataExt;

#[rstest]
#[case(IF_UNMODIFIED_SINCE, Duration::days(1), StatusCode::OK)]
#[case(IF_UNMODIFIED_SINCE, Duration::days(0), StatusCode::OK)]
#[case(IF_UNMODIFIED_SINCE, Duration::days(-1), StatusCode::PRECONDITION_FAILED)]
#[case(IF_MODIFIED_SINCE, Duration::days(1), StatusCode::NOT_MODIFIED)]
#[case(IF_MODIFIED_SINCE, Duration::days(0), StatusCode::NOT_MODIFIED)]
#[case(IF_MODIFIED_SINCE, Duration::days(-1), StatusCode::OK)]
fn get_file_with_if_modified_since_condition(
    #[case] header_condition: HeaderName,
    #[case] duration_after_file_modified: Duration,
    #[case] expected_code: StatusCode,
    server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}index.html", server.url())).send()?;

    let last_modified = resp
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|h| h.to_str().ok())
        .and_then(|s| DateTime::parse_from_rfc2822(s).ok())
        .expect("Received no valid last modified header");

    let req_modified_time = (last_modified + duration_after_file_modified)
        .format("%a, %d %b %Y %T GMT")
        .to_string();

    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header(header_condition, req_modified_time)
        .send()?;

    assert_eq!(resp.status(), expected_code);
    Ok(())
}

fn same_etag(etag: &str) -> String {
    etag.to_owned()
}

/// 生成一个与 `etag` 不同、但**语法合法**（引号包裹）的 ETag。
/// 必须保持合法：非法值（如引号外拖尾巴的 `"..."1234`）依赖 headers
/// 库的宽松解析才会被当作"不同的 ETag"——解析一旦收紧，头会被静默
/// 忽略，"不匹配"用例就退化成没测到任何东西的空转通过。
/// Produce an ETag that differs from `etag` but remains syntactically valid and quoted. An invalid
/// value such as `"..."1234` is considered different only under permissive header parsing; stricter
/// parsing would silently ignore it and let the mismatch case pass without exercising the condition.
fn different_etag(etag: &str) -> String {
    format!("\"{}-different\"", etag.trim_matches('"'))
}

#[rstest]
#[case(IF_MATCH, same_etag, StatusCode::OK)]
#[case(IF_MATCH, different_etag, StatusCode::PRECONDITION_FAILED)]
#[case(IF_NONE_MATCH, same_etag, StatusCode::NOT_MODIFIED)]
#[case(IF_NONE_MATCH, different_etag, StatusCode::OK)]
fn get_file_with_etag_match(
    #[case] header_condition: HeaderName,
    #[case] etag_modifier: fn(&str) -> String,
    #[case] expected_code: StatusCode,
    server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}index.html", server.url())).send()?;

    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|h| h.to_str().ok())
        .expect("Received no valid etag header");

    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header(header_condition, etag_modifier(etag))
        .send()?;

    assert_eq!(resp.status(), expected_code);
    Ok(())
}

#[rstest]
#[case(same_etag, StatusCode::NO_CONTENT)]
#[case(different_etag, StatusCode::PRECONDITION_FAILED)]
fn put_file_with_if_match(
    #[case] etag_modifier: fn(&str) -> String,
    #[case] expected_code: StatusCode,
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    // 获取当前 ETag 后用 If-Match 条件覆盖；过期 ETag 必须以 412 拒绝并发覆盖。
    // Fetch the ETag then overwrite with If-Match; a stale tag must reject concurrent replacement.
    let resp = fetch!(b"HEAD", format!("{}test.txt", server.url())).send()?;
    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|h| h.to_str().ok())
        .expect("Received no valid etag header")
        .to_string();

    let resp = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .header(IF_MATCH, etag_modifier(&etag))
        .body(b"updated".to_vec())
        .send()?;

    assert_eq!(resp.status(), expected_code);
    Ok(())
}

#[rstest]
#[case(IF_MATCH, "not-an-entity-tag")]
#[case(IF_NONE_MATCH, "not-an-entity-tag")]
#[case(IF_UNMODIFIED_SINCE, "not-an-http-date")]
fn malformed_write_preconditions_fail_closed_without_side_effects(
    #[case] header: HeaderName,
    #[case] value: &str,
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let path = server.path().join("test.txt");
    let before = std::fs::read(&path)?;
    let resp = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .header(header.clone(), value)
        .body(b"must not be committed".to_vec())
        .send()?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read(path)?, before);

    let missing = server.path().join("condition-missing");
    let resp = fetch!(
        b"PUT",
        format!("{}condition-missing/file.txt", server.url())
    )
    .header(header, value)
    .body(b"must not create ancestors".to_vec())
    .send()?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert!(!missing.exists());
    Ok(())
}

#[rstest]
#[case(IF_MATCH, "not-an-entity-tag")]
#[case(IF_NONE_MATCH, "not-an-entity-tag")]
#[case(IF_UNMODIFIED_SINCE, "not-an-http-date")]
#[case(IF_MODIFIED_SINCE, "not-an-http-date")]
#[case(IF_RANGE, "not-a-validator")]
fn malformed_read_conditions_are_not_silently_ignored(
    #[case] header: HeaderName,
    #[case] value: &str,
    server: TestServer,
) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header(header, value)
        .send()?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[rstest]
#[case(b"GET")]
#[case(b"HEAD")]
fn malformed_read_condition_wins_over_missing_target(
    #[case] method: &[u8],
    server: TestServer,
) -> Result<(), Error> {
    let response = reqwest::blocking::Client::new()
        .request(
            reqwest::Method::from_bytes(method)?,
            format!("{}missing-conditional", server.url()),
        )
        .header(IF_MATCH, "not-an-entity-tag")
        .send()?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[rstest]
#[case(b"GET")]
#[case(b"HEAD")]
fn if_match_on_missing_read_target_is_412(
    #[case] method: &[u8],
    server: TestServer,
) -> Result<(), Error> {
    let response = reqwest::blocking::Client::new()
        .request(
            reqwest::Method::from_bytes(method)?,
            format!("{}missing-conditional", server.url()),
        )
        .header(IF_MATCH, "*")
        .send()?;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    Ok(())
}

#[rstest]
fn repeated_if_none_match_wildcard_is_rejected(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append(IF_NONE_MATCH, "*".parse()?);
    headers.append(IF_NONE_MATCH, "*".parse()?);

    let path = server.path().join("test.txt");
    let before = std::fs::read(&path)?;
    let resp = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .headers(headers.clone())
        .body(b"must not overwrite".to_vec())
        .send()?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(std::fs::read(path)?, before);

    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .headers(headers)
        .send()?;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn malformed_condition_cases() -> Result<Vec<(&'static str, HeaderMap)>, Error> {
    let one = |name: HeaderName, value: HeaderValue| {
        let mut headers = HeaderMap::new();
        headers.insert(name, value);
        headers
    };

    let mut duplicate_if_match_wildcard = HeaderMap::new();
    duplicate_if_match_wildcard.append(IF_MATCH, HeaderValue::from_static("*"));
    duplicate_if_match_wildcard.append(IF_MATCH, HeaderValue::from_static("*"));

    let mut duplicate_if_none_match_wildcard = HeaderMap::new();
    duplicate_if_none_match_wildcard.append(IF_NONE_MATCH, HeaderValue::from_static("*"));
    duplicate_if_none_match_wildcard.append(IF_NONE_MATCH, HeaderValue::from_static("*"));

    let mut duplicate_if_unmodified_since = HeaderMap::new();
    duplicate_if_unmodified_since.append(
        IF_UNMODIFIED_SINCE,
        HeaderValue::from_static("Sat, 29 Oct 1994 19:43:31 GMT"),
    );
    duplicate_if_unmodified_since.append(
        IF_UNMODIFIED_SINCE,
        HeaderValue::from_static("Sun, 30 Oct 1994 19:43:31 GMT"),
    );

    let mut duplicate_if_modified_since = HeaderMap::new();
    duplicate_if_modified_since.append(
        IF_MODIFIED_SINCE,
        HeaderValue::from_static("Sat, 29 Oct 1994 19:43:31 GMT"),
    );
    duplicate_if_modified_since.append(
        IF_MODIFIED_SINCE,
        HeaderValue::from_static("Sun, 30 Oct 1994 19:43:31 GMT"),
    );

    let mut duplicate_if_range = HeaderMap::new();
    duplicate_if_range.append(IF_RANGE, HeaderValue::from_static("\"one\""));
    duplicate_if_range.append(IF_RANGE, HeaderValue::from_static("\"two\""));

    Ok(vec![
        (
            "unquoted If-Match",
            one(IF_MATCH, HeaderValue::from_static("unquoted")),
        ),
        (
            "unterminated If-None-Match",
            one(IF_NONE_MATCH, HeaderValue::from_static("\"unterminated")),
        ),
        (
            "non-UTF-8 If-Match",
            one(IF_MATCH, HeaderValue::from_bytes(b"\"\xff\"")?),
        ),
        (
            "non-UTF-8 If-None-Match",
            one(IF_NONE_MATCH, HeaderValue::from_bytes(b"\"\xff\"")?),
        ),
        (
            "non-UTF-8 If-Range",
            one(IF_RANGE, HeaderValue::from_bytes(b"\"\xff\"")?),
        ),
        (
            "If-Match wildcard mixed with a tag",
            one(IF_MATCH, HeaderValue::from_static("*, \"tag\"")),
        ),
        (
            "If-None-Match wildcard mixed with a tag",
            one(IF_NONE_MATCH, HeaderValue::from_static("*, \"tag\"")),
        ),
        (
            "invalid If-Unmodified-Since",
            one(IF_UNMODIFIED_SINCE, HeaderValue::from_static("not-a-date")),
        ),
        (
            "invalid If-Modified-Since",
            one(IF_MODIFIED_SINCE, HeaderValue::from_static("not-a-date")),
        ),
        (
            "invalid If-Range",
            one(IF_RANGE, HeaderValue::from_static("not-a-validator")),
        ),
        ("duplicate If-Match wildcard", duplicate_if_match_wildcard),
        (
            "duplicate If-None-Match wildcard",
            duplicate_if_none_match_wildcard,
        ),
        (
            "duplicate If-Unmodified-Since",
            duplicate_if_unmodified_since,
        ),
        ("duplicate If-Modified-Since", duplicate_if_modified_since),
        ("duplicate If-Range", duplicate_if_range),
    ])
}

fn root_entry_names(server: &TestServer) -> Result<Vec<std::ffi::OsString>, Error> {
    let mut names = std::fs::read_dir(server.path())?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<Result<Vec<_>, _>>()?;
    names.sort();
    Ok(names)
}

fn request_for_write_method(
    client: &reqwest::blocking::Client,
    server: &TestServer,
    method: &'static [u8],
    source: &str,
    headers: HeaderMap,
) -> Result<reqwest::blocking::RequestBuilder, Error> {
    let method = reqwest::Method::from_bytes(method)?;
    let mut request = client
        .request(method.clone(), format!("{}{source}", server.url()))
        .headers(headers);
    request = match method.as_str() {
        "PUT" => request.body("rejected replacement"),
        "MOVE" => request.header(
            "Destination",
            format!("{}condition-destination", server.url()),
        ),
        _ => request,
    };
    Ok(request)
}

#[rstest]
fn every_write_method_rejects_malformed_conditions_without_side_effects(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let target = server.path().join("test.txt");
    let before_metadata = std::fs::metadata(&target)?;
    let before_content = std::fs::read(&target)?;
    let before_entries = root_entry_names(&server)?;
    let before_etag = fetch!(b"HEAD", format!("{}test.txt", server.url()))
        .send()?
        .headers()
        .get(ETAG)
        .cloned()
        .expect("fixture file has an ETag");

    for method in [b"PUT".as_slice(), b"DELETE", b"MOVE", b"MKCOL"] {
        for (case, headers) in malformed_condition_cases()? {
            let source = if method == b"MKCOL" {
                "condition-collection"
            } else {
                "test.txt"
            };
            let response =
                request_for_write_method(&client, &server, method, source, headers)?.send()?;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "{} with {case}",
                String::from_utf8_lossy(method)
            );
        }
    }

    let after_metadata = std::fs::metadata(&target)?;
    assert_eq!(after_metadata.dev(), before_metadata.dev());
    assert_eq!(after_metadata.ino(), before_metadata.ino());
    assert_eq!(std::fs::read(&target)?, before_content);
    assert_eq!(root_entry_names(&server)?, before_entries);
    assert!(!server.path().join("condition-collection").exists());
    assert!(!server.path().join("condition-destination").exists());
    assert!(root_entry_names(&server)?.iter().all(|name| {
        name.to_str()
            .is_none_or(|name| !name.starts_with(".ram-upload-") || !name.ends_with(".tmp"))
    }));
    let after_etag = fetch!(b"HEAD", format!("{}test.txt", server.url()))
        .send()?
        .headers()
        .get(ETAG)
        .cloned()
        .expect("fixture file still has an ETag");
    assert_eq!(after_etag, before_etag);
    Ok(())
}

#[rstest]
fn malformed_conditions_win_over_missing_target_for_every_write_method(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(IF_MATCH, HeaderValue::from_static("not-an-entity-tag"));

    for (method, source) in [
        (b"PUT".as_slice(), "missing-parent/new.txt"),
        (b"DELETE".as_slice(), "missing-delete"),
        (b"MOVE".as_slice(), "missing-move"),
        (b"MKCOL".as_slice(), "missing-collection"),
    ] {
        let response =
            request_for_write_method(&client, &server, method, source, headers.clone())?.send()?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "{} missing-target precedence",
            String::from_utf8_lossy(method)
        );
    }

    assert!(!server.path().join("missing-parent").exists());
    assert!(!server.path().join("condition-destination").exists());
    Ok(())
}

#[rstest]
fn if_match_on_a_missing_target_is_412_for_every_write_method(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let mut headers = HeaderMap::new();
    headers.insert(IF_MATCH, HeaderValue::from_static("*"));

    for (method, source) in [
        (b"PUT".as_slice(), "absent-put"),
        (b"DELETE".as_slice(), "absent-delete"),
        (b"MOVE".as_slice(), "absent-move"),
        (b"MKCOL".as_slice(), "absent-collection"),
    ] {
        let response =
            request_for_write_method(&client, &server, method, source, headers.clone())?.send()?;
        assert_eq!(
            response.status(),
            StatusCode::PRECONDITION_FAILED,
            "{} missing If-Match",
            String::from_utf8_lossy(method)
        );
        assert!(!server.path().join(source).exists());
    }
    assert!(!server.path().join("condition-destination").exists());
    Ok(())
}

#[rstest]
fn missing_target_without_conditions_is_404_for_existing_only_methods(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();

    for method in [b"GET".as_slice(), b"HEAD"] {
        let response = client
            .request(
                reqwest::Method::from_bytes(method)?,
                format!("{}absent-read", server.url()),
            )
            .send()?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{} missing without conditions",
            String::from_utf8_lossy(method)
        );
    }

    for (method, source) in [
        (b"DELETE".as_slice(), "absent-unconditional-delete"),
        (b"MOVE".as_slice(), "absent-unconditional-move"),
    ] {
        let response =
            request_for_write_method(&client, &server, method, source, HeaderMap::new())?.send()?;
        assert_eq!(
            response.status(),
            StatusCode::NOT_FOUND,
            "{} missing without conditions",
            String::from_utf8_lossy(method)
        );
        assert!(!server.path().join(source).exists());
    }

    assert!(!server.path().join("condition-destination").exists());
    Ok(())
}

#[rstest]
fn contradictory_wildcards_are_valid_but_fail_unsafe_preconditions(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let path = server.path().join("test.txt");
    let before = std::fs::read(&path)?;
    let response = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .header(IF_MATCH, "*")
        .header(IF_NONE_MATCH, "*")
        .body("must not replace")
        .send()?;
    assert_eq!(response.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(std::fs::read(path)?, before);
    Ok(())
}

#[rstest]
#[case("not-an-entity-tag", StatusCode::BAD_REQUEST)]
#[case("*", StatusCode::PRECONDITION_FAILED)]
fn mkcol_preconditions_fail_closed_without_creating_the_target(
    #[case] value: &str,
    #[case] expected: StatusCode,
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let target = server.path().join("conditional-directory");
    let resp = fetch!(b"MKCOL", format!("{}conditional-directory", server.url()))
        .header(IF_MATCH, value)
        .send()?;
    assert_eq!(resp.status(), expected);
    assert!(!target.exists());
    Ok(())
}

/// RFC 9110 §13.2.2：ETag 校验头与时间戳校验头同时出现时，必须只看
/// ETag——两个方向各验一例。时间戳只有秒级精度，同一秒内的多次修改
/// 只有 ETag 能区分。
/// RFC 9110 §13.2.2 requires ETag conditions to take precedence when entity-tag and date validators
/// coexist; test both directions. Dates have only second precision, so only ETags distinguish
/// multiple changes within one second.
#[rstest]
fn etag_conditions_win_over_date_conditions(server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let resp = fetch!(b"HEAD", &url).send()?;
    let etag = resp
        .headers()
        .get(ETAG)
        .and_then(|h| h.to_str().ok())
        .expect("Received no valid etag header")
        .to_string();
    let last_modified = resp
        .headers()
        .get(LAST_MODIFIED)
        .and_then(|h| h.to_str().ok())
        .expect("Received no valid last modified header")
        .to_string();

    // 单看 If-Modified-Since（等于当前修改时间）会回 304，但不匹配的
    // If-None-Match 说明实体已变——必须回 200。
    // If-Modified-Since alone would yield 304, but the mismatching If-None-Match proves the entity
    // changed and must win with 200.
    let resp = fetch!(b"GET", &url)
        .header(IF_NONE_MATCH, different_etag(&etag))
        .header(IF_MODIFIED_SINCE, &last_modified)
        .send()?;
    assert_eq!(resp.status(), StatusCode::OK);

    // 单看 If-Unmodified-Since（远古日期）会回 412，但匹配的 If-Match
    // 必须获胜——回 200。
    // If-Unmodified-Since alone would yield 412, but the matching If-Match takes precedence with 200.
    let resp = fetch!(b"GET", &url)
        .header(IF_MATCH, same_etag(&etag))
        .header(IF_UNMODIFIED_SINCE, "Sat, 01 Jan 2000 00:00:00 GMT")
        .send()?;
    assert_eq!(resp.status(), StatusCode::OK);
    Ok(())
}

#[rstest]
fn not_modified_keeps_current_validators(server: TestServer) -> Result<(), Error> {
    let url = format!("{}index.html", server.url());
    let initial = fetch!(b"HEAD", &url).send()?;
    let etag = initial.headers().get(ETAG).unwrap().clone();
    let last_modified = initial.headers().get(LAST_MODIFIED).unwrap().clone();

    let resp = fetch!(b"GET", &url)
        .header(IF_NONE_MATCH, etag.clone())
        .send()?;
    assert_eq!(resp.status(), StatusCode::NOT_MODIFIED);
    assert_eq!(resp.headers().get(ETAG).unwrap(), etag);
    assert_eq!(resp.headers().get(LAST_MODIFIED).unwrap(), last_modified);
    let cache_control = resp.headers().get(CACHE_CONTROL).unwrap().to_str()?;
    assert!(cache_control.contains("private"), "{cache_control}");
    assert!(cache_control.contains("no-cache"), "{cache_control}");
    Ok(())
}

#[rstest]
fn etag_changes_after_same_size_rewrite_with_restored_mtime(
    server: TestServer,
) -> Result<(), Error> {
    let path = server.path().join("etag-version.txt");
    std::fs::write(&path, b"first")?;
    let modified = std::fs::metadata(&path)?.modified()?;
    let url = format!("{}etag-version.txt", server.url());
    let first = fetch!(b"HEAD", &url).send()?;
    let first_etag = first.headers().get(ETAG).unwrap().clone();

    std::fs::write(&path, b"other")?;
    OpenOptions::new()
        .write(true)
        .open(&path)?
        .set_times(FileTimes::new().set_modified(modified))?;

    let second = fetch!(b"HEAD", &url).send()?;
    let second_etag = second.headers().get(ETAG).unwrap();
    assert_ne!(second_etag, first_etag);
    Ok(())
}

#[rstest]
fn small_files_use_content_strong_etags_while_large_files_are_weak(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let small_path = server.path().join("strong-etag.txt");
    std::fs::write(&small_path, b"content identity")?;
    let small_url = format!("{}strong-etag.txt", server.url());
    let small = fetch!(b"HEAD", &small_url).send()?;
    let strong = small.headers().get(ETAG).unwrap().to_str()?.to_string();
    assert!(strong.starts_with('"'), "expected a strong ETag: {strong}");
    assert!(strong.contains("sha256:"), "{strong}");

    let large_path = server.path().join("weak-etag.bin");
    std::fs::write(&large_path, vec![b'x'; 4 * 1024 * 1024 + 1])?;
    let large_url = format!("{}weak-etag.bin", server.url());
    let large = fetch!(b"HEAD", &large_url).send()?;
    let weak = large.headers().get(ETAG).unwrap().to_str()?.to_string();
    assert!(
        weak.starts_with("W/\"meta:"),
        "expected a weak ETag: {weak}"
    );

    // 弱验证器适用于缓存重验证…… / Weak validators are valid for cache revalidation...
    let not_modified = fetch!(b"GET", &large_url)
        .header(IF_NONE_MATCH, &weak)
        .send()?;
    assert_eq!(not_modified.status(), StatusCode::NOT_MODIFIED);
    // ……但绝不满足 If-Match 要求的强比较。 / ...but never satisfy If-Match's strong comparison.
    let precondition = fetch!(b"PUT", &large_url)
        .header(IF_MATCH, &weak)
        .body("replacement")
        .send()?;
    assert_eq!(precondition.status(), StatusCode::PRECONDITION_FAILED);
    assert_eq!(std::fs::metadata(large_path)?.len(), 4 * 1024 * 1024 + 1);
    Ok(())
}

#[rstest]
fn authenticated_cache_policy_separates_downloads_from_dynamic_views(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let download = fetch!(b"GET", format!("{}test.txt", server.url())).send()?;
    let download_policy = download.headers().get(CACHE_CONTROL).unwrap().to_str()?;
    assert!(download_policy.contains("private"), "{download_policy}");
    assert!(download_policy.contains("no-cache"), "{download_policy}");
    assert!(!download_policy.contains("no-store"), "{download_policy}");
    assert!(
        !download.headers().contains_key(VARY),
        "private, revalidated responses do not need Vary: Authorization"
    );

    for relative in ["?simple", "?json", "test.txt?view"] {
        let response = fetch!(b"GET", format!("{}{relative}", server.url())).send()?;
        assert_eq!(response.status(), StatusCode::OK, "{relative}");
        let policy = response.headers().get(CACHE_CONTROL).unwrap().to_str()?;
        assert!(policy.contains("private"), "{relative}: {policy}");
        assert!(policy.contains("no-store"), "{relative}: {policy}");
    }

    Ok(())
}

/// 每个动态 GET 表示都拥有由最终字节派生的强验证器。HEAD 必须选择同一组字节（但不发送），
/// 因而无论从哪种方法取得验证器，目录、元数据、查看和搜索视图都具有完全一致的
/// 200/304/412 语义。
///
/// Every generated GET representation owns a byte-derived strong validator. HEAD must select the
/// same bytes (without sending them), so a validator learned through either method has identical
/// 200/304/412 semantics for directory, metadata, viewer, and search views.
#[rstest]
fn generated_get_and_head_views_share_exact_conditional_semantics(
    #[with(&["--allow-search"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    for relative in ["", "?simple", "?json", "?q=test", "test.txt?view"] {
        let url = format!("{}{relative}", server.url());
        let get = client.get(&url).send()?;
        assert_eq!(get.status(), StatusCode::OK, "GET {relative}");
        let get_etag = get
            .headers()
            .get(ETAG)
            .cloned()
            .unwrap_or_else(|| panic!("GET {relative} omitted ETag"));
        let get_length = get
            .headers()
            .get("content-length")
            .cloned()
            .unwrap_or_else(|| panic!("GET {relative} omitted Content-Length"));
        let get_body = get.bytes()?;
        assert_eq!(
            get_length.to_str()?.parse::<usize>()?,
            get_body.len(),
            "GET {relative} length"
        );

        let head = client.head(&url).send()?;
        assert_eq!(head.status(), StatusCode::OK, "HEAD {relative}");
        if let Some(etag) = head.headers().get(ETAG) {
            assert_eq!(etag, &get_etag, "HEAD {relative} ETag");
        }
        if let Some(length) = head.headers().get("content-length") {
            assert_eq!(length, &get_length, "HEAD {relative} length");
        }
        assert!(head.bytes()?.is_empty(), "HEAD {relative} sent a body");

        for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
            let not_modified = client
                .request(method.clone(), &url)
                .header(IF_NONE_MATCH, get_etag.clone())
                .send()?;
            assert_eq!(
                not_modified.status(),
                StatusCode::NOT_MODIFIED,
                "{method} {relative} If-None-Match"
            );
            assert_eq!(not_modified.headers().get(ETAG), Some(&get_etag));
            if let Some(length) = not_modified.headers().get("content-length") {
                assert_eq!(length, &get_length);
            }
            assert!(not_modified.bytes()?.is_empty());
        }

        let etag = get_etag.to_str()?;
        for method in [reqwest::Method::GET, reqwest::Method::HEAD] {
            let failed = client
                .request(method.clone(), &url)
                .header(IF_MATCH, different_etag(etag))
                .send()?;
            assert_eq!(
                failed.status(),
                StatusCode::PRECONDITION_FAILED,
                "{method} {relative} stale If-Match"
            );
            assert_eq!(failed.headers().get("content-length").unwrap(), "0");
            assert!(failed.bytes()?.is_empty());

            let matched = client
                .request(method.clone(), &url)
                .header(IF_MATCH, etag)
                .send()?;
            assert_eq!(
                matched.status(),
                StatusCode::OK,
                "{method} {relative} If-Match"
            );
            assert_eq!(matched.headers().get(ETAG), Some(&get_etag));
            assert_eq!(matched.headers().get("content-length"), Some(&get_length));
        }

        let wildcard_head = client.head(&url).header(IF_NONE_MATCH, "*").send()?;
        assert_eq!(
            wildcard_head.status(),
            StatusCode::NOT_MODIFIED,
            "HEAD {relative} wildcard"
        );
        assert!(wildcard_head.bytes()?.is_empty());
    }
    Ok(())
}
