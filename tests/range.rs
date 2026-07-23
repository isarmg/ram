#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, TestServer, server};
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use rstest::rstest;

#[rstest]
fn get_file_range(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-6"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes 0-6/18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "7");
    assert_eq!(resp.text()?, "This is");
    Ok(())
}

#[rstest]
fn duplicate_range_fields_are_rejected_instead_of_selecting_one(
    server: TestServer,
) -> Result<(), Error> {
    let mut headers = HeaderMap::new();
    headers.append("range", HeaderValue::from_static("bytes=0-1"));
    headers.append("range", HeaderValue::from_static("bytes=4-5"));
    let response = fetch!(b"GET", format!("{}index.html", server.url()))
        .headers(headers)
        .send()?;
    assert_eq!(response.status(), 400);
    assert_eq!(response.headers().get("content-length").unwrap(), "0");
    assert!(response.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn get_file_range_beyond(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=12-20"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 12-17/18"
    );
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "6");
    assert_eq!(resp.text()?, "x.html");
    Ok(())
}

#[rstest]
fn get_file_range_invalid(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=20-"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

fn parse_multipart_body<'a>(body: &'a str, boundary: &str) -> Vec<(HeaderMap, &'a str)> {
    body.split(&format!("--{boundary}"))
        .filter(|part| !part.is_empty() && *part != "--\r\n")
        .map(|part| {
            let (head, body) = part.trim_ascii().split_once("\r\n\r\n").unwrap();
            let headers = head
                .split("\r\n")
                .fold(HeaderMap::new(), |mut headers, header| {
                    let (key, value) = header.split_once(":").unwrap();
                    let key = HeaderName::from_bytes(key.as_bytes()).unwrap();
                    let value = HeaderValue::from_str(value.trim_ascii_start()).unwrap();
                    headers.insert(key, value);
                    headers
                });
            (headers, body)
        })
        .collect()
}

#[rstest]
fn get_file_multipart_range(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-11, 6-17"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");

    let content_type = resp
        .headers()
        .get("content-type")
        .unwrap()
        .to_str()?
        .to_string();
    assert!(content_type.starts_with("multipart/byteranges; boundary="));

    let boundary = content_type.split_once('=').unwrap().1.trim_ascii_start();
    assert!(!boundary.is_empty());

    let content_length: u64 = resp
        .headers()
        .get("content-length")
        .unwrap()
        .to_str()?
        .parse()?;

    let body = resp.bytes()?;
    // 预计算的 Content-Length 必须与实际发出的字节数严格一致：
    // 差一个字节客户端就会截断内容或挂起等待。
    // Precomputed Content-Length must exactly match emitted bytes; one byte of error truncates the
    // client response or makes it wait indefinitely.
    assert_eq!(body.len() as u64, content_length);

    let body = std::str::from_utf8(&body)?;
    let parts = parse_multipart_body(body, boundary);
    assert_eq!(parts.len(), 2);

    let (headers, body) = &parts[0];
    assert_eq!(headers.get("content-range").unwrap(), "bytes 0-11/18");
    assert_eq!(*body, "This is inde");

    let (headers, body) = &parts[1];
    assert_eq!(headers.get("content-range").unwrap(), "bytes 6-17/18");
    assert_eq!(*body, "s index.html");

    Ok(())
}

#[rstest]
fn get_file_multipart_range_retains_satisfiable_members(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-6, 20-30"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes 0-6/18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    assert_eq!(resp.headers().get("content-length").unwrap(), "7");
    assert_eq!(resp.text()?, "This is");
    Ok(())
}

#[rstest]
fn get_file_multipart_range_too_many_ranges(server: TestServer) -> Result<(), Error> {
    let range = std::iter::repeat_n("0-0", 17).collect::<Vec<_>>().join(",");
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_str(&format!("bytes={range}"))?)
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn get_file_range_rejects_seventeenth_member_before_parsing(
    server: TestServer,
) -> Result<(), Error> {
    let mut ranges = vec!["0-0"; 16];
    ranges.push("malformed");
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header(
            "range",
            HeaderValue::from_str(&format!("bytes={}", ranges.join(",")))?,
        )
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn get_file_range_rejects_oversized_raw_header(server: TestServer) -> Result<(), Error> {
    let range = format!("bytes=0-{}", "9".repeat(9 * 1024));
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_str(&range)?)
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn get_file_multipart_range_total_bytes_over_limit(server: TestServer) -> Result<(), Error> {
    const MAX_MULTIPART_RANGE_BYTES: u64 = 64 * 1024 * 1024;
    let size = MAX_MULTIPART_RANGE_BYTES + 1;
    std::fs::File::create(server.path().join("large.bin"))?.set_len(size)?;

    // 两个分别有效的成员合计超过响应预算一字节，从而覆盖解析后 multipart 416 路径。
    // Two individually valid members exceed the aggregate response budget by one byte and exercise multipart 416.
    let midpoint = size / 2;
    let range = format!("bytes=0-{},{}-{}", midpoint - 1, midpoint, size - 1);
    let resp = fetch!(b"GET", format!("{}large.bin", server.url()))
        .header("range", HeaderValue::from_str(&range)?)
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        format!("bytes */{size}").as_str()
    );
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn get_file_range_reversed(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=10-1"))
        .send()?;
    // 反向区间是畸形语法，并非语法有效但不可满足的范围；项目 HTTP 契约分别映射为 400/416。
    // A reversed interval is malformed, not merely unsatisfiable; the HTTP contract maps these to 400 and 416.
    assert_eq!(resp.status(), 400);
    assert!(!resp.headers().contains_key("content-range"));
    Ok(())
}

#[rstest]
fn get_file_multipart_range_reversed(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=10-1,20-2"))
        .send()?;
    assert_eq!(resp.status(), 400);
    assert!(!resp.headers().contains_key("content-range"));
    Ok(())
}

#[rstest]
fn get_file_range_suffix_larger_than_file(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=-999"))
        .send()?;
    assert_eq!(resp.status(), 206);
    assert_eq!(
        resp.headers().get("content-range").unwrap(),
        "bytes 0-17/18"
    );
    assert_eq!(resp.text()?, "This is index.html");
    Ok(())
}

#[rstest]
fn zero_suffix_range_is_unsatisfiable_without_panicking(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"GET", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=-0"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */18");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn range_on_empty_file_is_unsatisfiable_without_panicking(server: TestServer) -> Result<(), Error> {
    std::fs::write(server.path().join("empty.txt"), [])?;
    let resp = fetch!(b"GET", format!("{}empty.txt", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-"))
        .send()?;
    assert_eq!(resp.status(), 416);
    assert_eq!(resp.headers().get("content-range").unwrap(), "bytes */0");
    assert_eq!(resp.headers().get("accept-ranges").unwrap(), "bytes");
    Ok(())
}

#[rstest]
fn head_ignores_range(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"HEAD", format!("{}index.html", server.url()))
        .header("range", HeaderValue::from_static("bytes=0-6"))
        .send()?;
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers().get("content-length").unwrap(), "18");
    assert!(!resp.headers().contains_key("content-range"));
    assert!(resp.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn if_range_only_accepts_a_strong_current_entity_tag(server: TestServer) -> Result<(), Error> {
    let url = format!("{}test.txt", server.url());
    let validators = fetch!(b"HEAD", &url).send()?;
    let etag = validators.headers().get("etag").unwrap().clone();
    let last_modified = validators.headers().get("last-modified").unwrap().clone();

    let partial = fetch!(b"GET", &url)
        .header("range", "bytes=0-0")
        .header("if-range", etag.clone())
        .send()?;
    assert_eq!(partial.status(), 206);
    assert_eq!(
        partial.headers().get("content-range").unwrap(),
        "bytes 0-0/16"
    );
    assert_eq!(partial.bytes()?.as_ref(), b"T");

    let weak = format!("W/{}", etag.to_str()?);
    let full_for_weak = fetch!(b"GET", &url)
        .header("range", "bytes=0-0")
        .header("if-range", weak)
        .send()?;
    assert_eq!(full_for_weak.status(), 200);
    assert!(!full_for_weak.headers().contains_key("content-range"));

    // Ram 不把秒级文件系统日期视为强字节验证器，因此 If-Range 日期安全回退为完整响应。
    // Ram does not treat second-granularity dates as strong byte validators, so If-Range safely falls back.
    let full_for_date = fetch!(b"GET", &url)
        .header("range", "bytes=0-0")
        .header("if-range", last_modified)
        .send()?;
    assert_eq!(full_for_date.status(), 200);
    assert!(!full_for_date.headers().contains_key("content-range"));
    Ok(())
}
