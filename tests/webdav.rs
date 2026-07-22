#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{
    Error, FILES, ServerProc, TEST_AUTH_RULE, TestServer, port, ram_command, server, tmpdir,
};
use rstest::rstest;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::process::Command;
use xml::escape::escape_str_pcdata;

fn listing_mutation_version(listing_url: &str) -> Result<String, Error> {
    let response = reqwest::blocking::get(listing_url)?;
    assert_eq!(response.status(), 200);
    let header = response
        .headers()
        .get("x-ram-mutation-version")
        .expect("a complete stable listing exposes its mutation version")
        .to_str()?
        .to_owned();
    let data: serde_json::Value = serde_json::from_str(&response.text()?)?;
    assert_eq!(
        data.get("mutation_version")
            .and_then(|value| value.as_str()),
        Some(header.as_str())
    );
    Ok(header)
}

const PROPPATCH_BODY: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<D:propertyupdate xmlns:D="DAV:" xmlns:T="urn:ram:test">
  <D:set><D:prop><T:color/></D:prop></D:set>
</D:propertyupdate>"#;

fn propfind_properties(namespace: &str, names: &[String]) -> String {
    let properties = names
        .iter()
        .map(|name| format!("<T:{name}/>"))
        .collect::<String>();
    format!(
        r#"<D:propfind xmlns:D="DAV:" xmlns:T="{namespace}"><D:prop>{properties}</D:prop></D:propfind>"#
    )
}

fn propfind_selector(selector: &str) -> String {
    format!(r#"<D:propfind xmlns:D="DAV:">{selector}</D:propfind>"#)
}

fn proppatch_properties(namespace: &str, names: &[String]) -> String {
    let properties = names
        .iter()
        .map(|name| format!("<T:{name}/>"))
        .collect::<String>();
    format!(
        r#"<D:propertyupdate xmlns:D="DAV:" xmlns:T="{namespace}"><D:set><D:prop>{properties}</D:prop></D:set></D:propertyupdate>"#
    )
}

fn property_names(count: usize) -> Vec<String> {
    (0..count).map(|index| format!("p{index:02}")).collect()
}

fn raw_chunked_mkcol(
    server: &TestServer,
    path: &str,
    encoded_chunks: &str,
) -> Result<String, Error> {
    let mut stream = TcpStream::connect(("127.0.0.1", server.port()))?;
    stream.write_all(
        format!(
            "MKCOL /{path} HTTP/1.1\r\nHost: localhost:{}\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{encoded_chunks}",
            server.port()
        )
        .as_bytes(),
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[rstest]
fn propfind_dir(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", format!("{}dir1", server.url()))
        .header("depth", "1")
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/dir1/</D:href>"));
    assert!(body.contains("<D:displayname>dir1</D:displayname>"));
    for f in FILES {
        assert!(body.contains(&format!("<D:href>/dir1/{}</D:href>", utils::encode_uri(f))));
        assert!(body.contains(&format!(
            "<D:displayname>{}</D:displayname>",
            escape_str_pcdata(f)
        )));
    }
    Ok(())
}

#[rstest]
fn propfind_dir_depth0(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", format!("{}dir1", server.url()))
        .header("depth", "0")
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/dir1/</D:href>"));
    assert!(body.contains("<D:displayname>dir1</D:displayname>"));
    assert_eq!(
        body.lines()
            .filter(|v| *v == "<D:status>HTTP/1.1 200 OK</D:status>")
            .count(),
        1
    );
    Ok(())
}

#[rstest]
fn propfind_dir_depth2(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", format!("{}dir1", server.url()))
        .header("depth", "2")
        .send()?;
    assert_eq!(resp.status(), 400);
    let body = resp.text()?;
    assert_eq!(body, "Invalid Depth header: expected 0, 1, or infinity");
    Ok(())
}

#[rstest]
#[case(None)]
#[case(Some("infinity"))]
#[case(Some("INFINITY"))]
fn propfind_implicit_and_explicit_infinity_use_finite_depth_dav_error(
    server: TestServer,
    #[case] depth: Option<&str>,
) -> Result<(), Error> {
    let mut request = fetch!(b"PROPFIND", format!("{}dir1", server.url()));
    if let Some(depth) = depth {
        request = request.header("depth", depth);
    }
    let resp = request.send()?;
    assert_eq!(resp.status(), 403);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/xml; charset=utf-8"
    );
    let body = resp.text()?;
    assert!(body.contains("<D:error"));
    assert!(body.contains("<D:propfind-finite-depth/>"));
    Ok(())
}

#[rstest]
fn propfind_404(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", format!("{}404", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn propfind_double_slash(server: TestServer) -> Result<(), Error> {
    // 含空段（`//`）的路径必须像折叠路径一样解析，而不是失败。
    // A path containing an empty segment (`//`) must resolve like the collapsed path rather than fail.
    let resp = fetch!(b"PROPFIND", format!("{}dir1//", server.url()))
        .header("depth", "0")
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/dir1/</D:href>"));
    Ok(())
}

#[rstest]
fn propfind_file(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPFIND", format!("{}test.html", server.url()))
        .header("depth", "0")
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/test.html</D:href>"));
    assert!(body.contains("<D:displayname>test.html</D:displayname>"));
    assert_eq!(
        body.lines()
            .filter(|v| *v == "<D:status>HTTP/1.1 200 OK</D:status>")
            .count(),
        1
    );
    Ok(())
}

#[rstest]
fn propname_and_explicit_properties_honor_depth_zero(server: TestServer) -> Result<(), Error> {
    let url = format!("{}dir1", server.url());

    let propname = propfind_selector("<D:propname/>");
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(propname)
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert_eq!(body.matches("<D:response>").count(), 1);
    assert!(body.contains("<D:displayname/>"));
    assert!(!body.contains("<D:displayname>dir1</D:displayname>"));
    assert!(!body.contains("/dir1/test.html"));

    let explicit = propfind_selector(
        r#"<D:prop xmlns:T="urn:ram:depth-zero"><D:displayname/><T:color/></D:prop>"#,
    );
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(explicit)
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert_eq!(body.matches("<D:response>").count(), 1);
    assert!(body.contains("<D:displayname>dir1</D:displayname>"));
    assert!(body.contains("HTTP/1.1 200 OK"));
    assert!(body.contains("HTTP/1.1 404 Not Found"));
    assert!(body.contains("color"));
    assert!(!body.contains("/dir1/test.html"));
    Ok(())
}

#[rstest]
fn configurable_budget_is_shared_by_propfind_propname_and_proppatch(
    #[with(&[
        "-A",
        "--max-webdav-properties",
        "8",
        "--max-webdav-rendered-properties",
        "8",
        "--max-webdav-response-size",
        "64K",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let file_url = format!("{}test.html", server.url());

    for count in [7, 8] {
        let body = propfind_properties("urn:ram:configured", &property_names(count));
        let resp = fetch!(b"PROPFIND", &file_url)
            .header("content-type", "application/xml")
            .header("depth", "0")
            .body(body)
            .send()?;
        assert_eq!(resp.status(), 207, "{count} properties should fit");
    }
    let body = propfind_properties("urn:ram:configured", &property_names(9));
    let resp = fetch!(b"PROPFIND", &file_url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);

    for selector in ["<D:allprop/>", "<D:propname/>"] {
        let resp = fetch!(b"PROPFIND", &file_url)
            .header("content-type", "application/xml")
            .header("depth", "0")
            .body(propfind_selector(selector))
            .send()?;
        assert_eq!(resp.status(), 207, "{selector} must share the budget");
    }

    // 八个属性恰好适合一个 Depth: 0 资源；Depth: 1 会保留根和至少一个子项，必须在渲染前失败。
    // Eight properties exactly fit one Depth: 0 resource; Depth: 1 must fail before rendering root plus child.
    let body = propfind_properties("urn:ram:configured", &property_names(8));
    let resp = fetch!(b"PROPFIND", format!("{}dir1", server.url()))
        .header("content-type", "application/xml")
        .header("depth", "1")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 507);

    for count in [7, 8] {
        let body = proppatch_properties("urn:ram:configured", &property_names(count));
        let resp = fetch!(b"PROPPATCH", &file_url)
            .header("content-type", "application/xml")
            .body(body)
            .send()?;
        assert_eq!(resp.status(), 207, "{count} updates should fit");
    }
    let body = proppatch_properties("urn:ram:configured", &property_names(9));
    let resp = fetch!(b"PROPPATCH", &file_url)
        .header("content-type", "application/xml")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);
    Ok(())
}

#[rstest]
fn curl_webdav_propfind_smoke(server: TestServer) -> Result<(), Error> {
    // 运行真实广泛部署的 DAV 客户端二进制，而非只通过 reqwest 重放请求；负载是命令行 DAV
    // 发现客户端常用属性集。
    // Run a real, widely deployed DAV client binary rather than replaying only through reqwest; the
    // payload is the property set commonly used by command-line DAV discovery clients.
    let request = propfind_selector(
        "<D:prop><D:displayname/><D:resourcetype/><D:getcontentlength/><D:getlastmodified/></D:prop>",
    );
    let output = Command::new("curl")
        .args([
            "--silent",
            "--show-error",
            "--user",
            "admin:admin",
            "--request",
            "PROPFIND",
            "--header",
            "Depth: 1",
            "--header",
            "Content-Type: application/xml",
            "--data-binary",
            &request,
            &format!("http://localhost:{}/dir1", server.port()),
        ])
        .output()?;
    assert!(
        output.status.success(),
        "curl failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let body = String::from_utf8(output.stdout)?;
    assert!(body.contains("<D:multistatus"));
    assert!(body.contains("<D:href>/dir1/</D:href>"));
    assert!(body.contains("<D:href>/dir1/test.html</D:href>"));
    Ok(())
}

#[rstest]
fn propfind_explicit_property_count_boundaries(server: TestServer) -> Result<(), Error> {
    let url = format!("{}test.html", server.url());

    // 显式空 selector 仍是畸形；空 HTTP 请求体是单独的 RFC allprop 简写，已有常规测试覆盖。
    // An explicitly empty selector is malformed; an empty HTTP body is the separate RFC allprop
    // shorthand already covered by the regular test.
    let empty = r#"<D:propfind xmlns:D="DAV:"><D:prop/></D:propfind>"#;
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(empty)
        .send()?;
    assert_eq!(resp.status(), 400);

    for count in [1, 64] {
        let body = propfind_properties("urn:ram:budget", &property_names(count));
        let resp = fetch!(b"PROPFIND", &url)
            .header("content-type", "application/xml")
            .header("depth", "0")
            .body(body)
            .send()?;
        assert_eq!(resp.status(), 207, "{count} properties should be accepted");
    }

    let body = propfind_properties("urn:ram:budget", &property_names(65));
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);
    assert_eq!(resp.text()?, "WebDAV property budget exceeded");
    Ok(())
}

#[rstest]
fn propfind_duplicate_properties_are_deduplicated_in_first_seen_order(
    server: TestServer,
) -> Result<(), Error> {
    let names = ["first", "second", "first", "third", "second"]
        .map(str::to_string)
        .to_vec();
    let body = propfind_properties("urn:ram:dedup", &names);
    let resp = fetch!(b"PROPFIND", format!("{}test.html", server.url()))
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    let first = body.find("<P0:first ").expect("first property missing");
    let second = body.find("<P1:second ").expect("second property missing");
    let third = body.find("<P2:third ").expect("third property missing");
    assert!(first < second && second < third);
    assert_eq!(body.matches(":first ").count(), 1);
    assert_eq!(body.matches(":second ").count(), 1);
    assert_eq!(body.matches(":third ").count(), 1);

    // selector 上限在去重后计费：重复本身不能放大响应，也不挤掉合法名称。
    // Selector limit is charged after deduplication, so repetition cannot amplify response or displace a valid name.
    let repeated = vec!["same".to_string(); 65];
    let body = propfind_properties("urn:ram:dedup", &repeated);
    let resp = fetch!(b"PROPFIND", format!("{}test.html", server.url()))
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);
    assert_eq!(resp.text()?.matches(":same ").count(), 1);
    Ok(())
}

#[rstest]
fn propfind_property_name_byte_budgets(server: TestServer) -> Result<(), Error> {
    let url = format!("{}test.html", server.url());

    // 共享一个中等长度命名空间的 64 个不同属性仍合法；驻留使解析器只保留一次命名空间。
    // Sixty-four distinct properties sharing one moderately long namespace remain valid because
    // interning retains that namespace only once.
    let accepted_namespace = "n".repeat(200);
    let body = propfind_properties(&accepted_namespace, &property_names(64));
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);

    // 单命名空间上限为包含边界，并独立于 64 KiB 请求体上限。
    // The per-namespace limit is inclusive and independent of the 64 KiB body limit.
    let max_namespace = "n".repeat(256);
    let body = propfind_properties(&max_namespace, &["color".to_string()]);
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);

    let oversized_namespace = "n".repeat(257);
    let body = propfind_properties(&oversized_namespace, &["color".to_string()]);
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);

    // 单个命名空间可合法，但全部唯一请求属性的扩展名可能超过总预算。
    // A namespace may be individually valid while all unique expanded names exceed aggregate budget.
    let body = propfind_properties(&max_namespace, &property_names(64));
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);
    Ok(())
}

#[rstest]
fn propfind_rejects_xml_10_illegal_namespace_characters(server: TestServer) -> Result<(), Error> {
    let body =
        r#"<D:propfind xmlns:D="DAV:" xmlns:T="urn:x&#1;"><D:prop><T:p/></D:prop></D:propfind>"#;
    let resp = fetch!(b"PROPFIND", format!("{}test.html", server.url()))
        .header("content-type", "application/xml")
        .header("depth", "0")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 400);
    assert!(!resp.bytes()?.contains(&1));
    Ok(())
}

#[rstest]
fn propfind_depth_one_stops_at_the_property_multiplication_budget(
    server: TestServer,
) -> Result<(), Error> {
    let directory = server.path().join("property-budget");
    std::fs::create_dir(&directory)?;
    for index in 0..1023 {
        std::fs::write(directory.join(format!("f{index:04}")), [])?;
    }
    let body = propfind_properties("x", &property_names(64));
    let url = format!("{}property-budget", server.url());
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "1")
        .body(body.clone())
        .send()?;
    assert_eq!(resp.status(), 207);

    std::fs::write(directory.join("f1023"), [])?;
    let resp = fetch!(b"PROPFIND", &url)
        .header("content-type", "application/xml")
        .header("depth", "1")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 507);
    assert_eq!(resp.text()?, "WebDAV response budget exceeded");
    Ok(())
}

#[rstest]
fn proppatch_file(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPPATCH", format!("{}test.html", server.url()))
        .header("content-type", "application/xml")
        .body(PROPPATCH_BODY)
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/test.html</D:href>"));
    assert!(body.contains("HTTP/1.1 403 Forbidden"));
    assert!(body.contains("color"));
    Ok(())
}

#[rstest]
fn proppatch_uses_the_same_property_budget(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let url = format!("{}test.html", server.url());
    let body = proppatch_properties("urn:ram:budget", &property_names(64));
    let resp = fetch!(b"PROPPATCH", &url)
        .header("content-type", "application/xml")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);

    let body = proppatch_properties("urn:ram:budget", &property_names(65));
    let resp = fetch!(b"PROPPATCH", &url)
        .header("content-type", "application/xml")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);
    assert_eq!(resp.text()?, "WebDAV property budget exceeded");

    // 本地名长度由共享 XML 名称解析器检查，而非只由 PROPFIND selector 转换检查；配置边界包含端点。
    // Local-name length is checked by the shared XML parser too, and the configured boundary is inclusive.
    let body = proppatch_properties("urn:ram:budget", &["p".repeat(128)]);
    let resp = fetch!(b"PROPPATCH", &url)
        .header("content-type", "application/xml")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 207);

    let body = proppatch_properties("urn:ram:budget", &["p".repeat(129)]);
    let resp = fetch!(b"PROPPATCH", &url)
        .header("content-type", "application/xml")
        .body(body)
        .send()?;
    assert_eq!(resp.status(), 422);
    Ok(())
}

#[rstest]
fn proppatch_escapes_href(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let filename = "xml&file.txt";
    std::fs::write(server.path().join(filename), "xml")?;
    let resp = fetch!(b"PROPPATCH", format!("{}{}", server.url(), filename))
        .header("content-type", "application/xml")
        .body(PROPPATCH_BODY)
        .send()?;
    assert_eq!(resp.status(), 207);
    let body = resp.text()?;
    assert!(body.contains("<D:href>/xml&amp;file.txt</D:href>"));
    assert!(!body.contains("<D:href>/xml&file.txt</D:href>"));
    Ok(())
}

#[rstest]
fn proppatch_empty_body_is_bad_request(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPPATCH", format!("{}test.html", server.url())).send()?;
    assert_eq!(resp.status(), 400);
    Ok(())
}

#[rstest]
fn proppatch_404(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"PROPPATCH", format!("{}404", server.url())).send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn mkcol_dir(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"MKCOL", format!("{}newdir", server.url())).send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
#[case("extension.xml", "<D:mkcol xmlns:D=\"DAV:\"/>")]
#[case("whitespace", " \n")]
fn mkcol_rejects_every_nonempty_entity_without_side_effect(
    #[case] name: &str,
    #[case] body: &str,
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let target = server.path().join(name);
    let response = fetch!(b"MKCOL", format!("{}{name}", server.url()))
        .header("content-type", "application/xml")
        .body(body.to_string())
        .send()?;
    assert_eq!(response.status(), 415);
    assert_eq!(response.text()?, "MKCOL request entities are not supported");
    assert!(
        !target.exists(),
        "rejected MKCOL must not create its target"
    );
    Ok(())
}

#[rstest]
fn mkcol_chunked_entity_is_415_and_chunked_empty_is_creation(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let rejected = raw_chunked_mkcol(&server, "chunked-rejected", "1\r\nx\r\n0\r\n\r\n")?;
    assert!(
        rejected.starts_with("HTTP/1.1 415 "),
        "unexpected response: {rejected}"
    );
    assert!(!server.path().join("chunked-rejected").exists());

    let accepted = raw_chunked_mkcol(&server, "chunked-empty", "0\r\n\r\n")?;
    assert!(
        accepted.starts_with("HTTP/1.1 201 "),
        "unexpected response: {accepted}"
    );
    assert!(server.path().join("chunked-empty").is_dir());
    Ok(())
}

#[rstest]
fn mkcol_not_allow_upload(server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"MKCOL", format!("{}newdir", server.url())).send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn mkcol_already_exists(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"MKCOL", format!("{}dir1", server.url())).send()?;
    assert_eq!(resp.status(), 405);
    Ok(())
}

#[rstest]
fn mkcol_missing_parent_is_conflict(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"MKCOL", format!("{}missing/child", server.url())).send()?;
    assert_eq!(resp.status(), 409);
    assert!(!server.path().join("missing").exists());
    Ok(())
}

#[rstest]
fn copy_file(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .send()?;
    // 新目标是创建而非覆盖。 / A new destination is a creation, not an overwrite.
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(new_url)?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

/// COPY/MOVE 指令均为单值字段，且 Destination 表示一个文件系统 URI，而不是查询资源；重复
/// 歧义或会被静默丢弃的 query 必须在任何变更前失败。
/// COPY/MOVE directives are singleton fields and Destination denotes one filesystem URI, not a
/// query resource. Ambiguous duplicates or a silently discarded query must fail before mutation.
#[rstest]
fn copy_move_reject_ambiguous_singletons_and_destination_queries(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let source = format!("{}test.html", server.url());
    for method in ["COPY", "MOVE"] {
        let method = reqwest::Method::from_bytes(method.as_bytes())?;

        let mut duplicate_destination = reqwest::header::HeaderMap::new();
        duplicate_destination.append(
            "destination",
            format!("{}duplicate-one.html", server.url()).parse()?,
        );
        duplicate_destination.append(
            "destination",
            format!("{}duplicate-two.html", server.url()).parse()?,
        );
        let response = client
            .request(method.clone(), &source)
            .headers(duplicate_destination)
            .send()?;
        assert_eq!(response.status(), 400, "{method} duplicate Destination");

        let mut duplicate_overwrite = reqwest::header::HeaderMap::new();
        duplicate_overwrite.append("overwrite", "T".parse()?);
        duplicate_overwrite.append("overwrite", "F".parse()?);
        let response = client
            .request(method.clone(), &source)
            .header(
                "destination",
                format!("{}duplicate-overwrite.html", server.url()),
            )
            .headers(duplicate_overwrite)
            .send()?;
        assert_eq!(response.status(), 400, "{method} duplicate Overwrite");

        let response = client
            .request(method.clone(), &source)
            .header(
                "destination",
                format!("{}query-target.html?view", server.url()),
            )
            .send()?;
        assert_eq!(response.status(), 400, "{method} Destination query");

        for destination in [
            "http:/scheme-without-authority.html",
            "urn:ram:scheme-target.html",
            "ftp://localhost/scheme-target.html",
            "//localhost/authority-without-scheme.html",
        ] {
            let response = client
                .request(method.clone(), &source)
                .header("destination", destination)
                .send()?;
            assert_eq!(response.status(), 400, "{method} Destination {destination}");
        }
    }

    assert!(server.path().join("test.html").is_file());
    for name in [
        "duplicate-one.html",
        "duplicate-two.html",
        "duplicate-overwrite.html",
        "query-target.html",
        "scheme-without-authority.html",
        "scheme-target.html",
        "authority-without-scheme.html",
    ] {
        assert!(!server.path().join(name).exists(), "{name}");
    }
    Ok(())
}

/// 一个完整稳定列表携带启动/revision 快照；进程中任意变更都会保守使其失效，因而基于旧 UI
/// 发起的危险操作不能触碰目标。
/// A stable complete listing carries one boot/revision snapshot. A mutation anywhere in this
/// process invalidates it conservatively, so a destructive action based on the old UI cannot touch
/// its target.
#[rstest]
fn stale_listing_version_rejects_delete_after_unrelated_mutation(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let version = listing_mutation_version(&format!("{}?json", server.url()))?;
    let mutation = fetch!(b"PUT", format!("{}unrelated.bin", server.url()))
        .body("new namespace entry")
        .send()?;
    assert_eq!(mutation.status(), 201);

    let rejected = fetch!(b"DELETE", format!("{}test.html", server.url()))
        .header("X-Ram-If-Mutation-Version", version)
        .send()?;
    assert_eq!(rejected.status(), 412);
    assert_eq!(rejected.headers().get("content-length").unwrap(), "0");
    assert!(server.path().join("test.html").is_file());
    Ok(())
}

/// 子树新增同样使父列表失效；重新获取的版本则允许预期 DELETE。
/// A subtree creation also invalidates a parent listing, while a newly fetched version permits the
/// intended DELETE.
#[rstest]
fn subtree_mutation_invalidates_listing_and_fresh_delete_succeeds(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let stale = listing_mutation_version(&format!("{}dir1/?json", server.url()))?;
    let created = fetch!(b"MKCOL", format!("{}dir1/new-child", server.url())).send()?;
    assert_eq!(created.status(), 201);

    let rejected = fetch!(b"DELETE", format!("{}dir1/test.html", server.url()))
        .header("X-Ram-If-Mutation-Version", stale)
        .send()?;
    assert_eq!(rejected.status(), 412);
    assert!(server.path().join("dir1/test.html").is_file());

    let fresh = listing_mutation_version(&format!("{}dir1/?json", server.url()))?;
    let deleted = fetch!(b"DELETE", format!("{}dir1/test.html", server.url()))
        .header("X-Ram-If-Mutation-Version", fresh)
        .send()?;
    assert_eq!(deleted.status(), 204);
    assert!(!server.path().join("dir1/test.html").exists());
    Ok(())
}

/// MOVE 与 DELETE 一样在持有全部锁后原子比较版本；过期请求保持源/目标不变，无该头的 DAV
/// 客户端仍保持兼容。
/// MOVE performs the same post-lock atomic version comparison as DELETE. A stale request keeps both
/// source and destination unchanged; a headerless DAV client remains backward compatible.
#[rstest]
fn move_version_is_atomic_and_headerless_clients_remain_compatible(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let stale = listing_mutation_version(&format!("{}?json", server.url()))?;
    let replacement = fetch!(b"PUT", format!("{}test.txt", server.url()))
        .body("replacement")
        .send()?;
    assert_eq!(replacement.status(), 204);

    let stale_destination = format!("{}stale-move.html", server.url());
    let rejected = fetch!(b"MOVE", format!("{}test.html", server.url()))
        .header("Destination", &stale_destination)
        .header("X-Ram-If-Mutation-Version", stale)
        .send()?;
    assert_eq!(rejected.status(), 412);
    assert!(server.path().join("test.html").is_file());
    assert!(!server.path().join("stale-move.html").exists());

    let compatible_destination = format!("{}compatible-move.html", server.url());
    let moved = fetch!(b"MOVE", format!("{}test.html", server.url()))
        .header("Destination", &compatible_destination)
        .send()?;
    assert_eq!(moved.status(), 201);
    assert!(!server.path().join("test.html").exists());
    assert!(server.path().join("compatible-move.html").is_file());
    Ok(())
}

/// 乐观条件是具有紧凑规范语法的严格单值头；拒绝畸形或重复值时不得删除或移动任何对象。
/// The optimistic condition is a strict singleton with a compact canonical grammar. Rejecting a
/// malformed or duplicate value must happen without deleting or moving anything.
#[rstest]
fn mutation_version_rejects_malformed_and_duplicate_headers_without_side_effects(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    for invalid in [
        "not-a-version",
        "00000000-0000-0000-0000-000000000000.00",
        "00000000-0000-0000-0000-000000000000.18446744073709551616",
    ] {
        let response = client
            .delete(format!("{}test.html", server.url()))
            .header("X-Ram-If-Mutation-Version", invalid)
            .send()?;
        assert_eq!(response.status(), 400, "{invalid}");
        assert!(server.path().join("test.html").is_file());
    }

    let canonical = listing_mutation_version(&format!("{}?json", server.url()))?;
    let mut duplicate = reqwest::header::HeaderMap::new();
    duplicate.append("x-ram-if-mutation-version", canonical.parse()?);
    duplicate.append("x-ram-if-mutation-version", canonical.parse()?);
    let response = client
        .delete(format!("{}test.html", server.url()))
        .headers(duplicate)
        .send()?;
    assert_eq!(response.status(), 400);
    assert!(server.path().join("test.html").is_file());
    Ok(())
}

/// 启动标识防止令牌跨进程重启存活，即使文件系统与初始数字 revision 看起来完全相同也会拒绝。
/// The boot component prevents a token surviving process restart even when the filesystem and
/// numeric revision initially look identical.
#[rstest]
fn mutation_version_from_previous_server_boot_is_stale(
    tmpdir: assert_fs::fixture::TempDir,
    port: u16,
) -> Result<(), Error> {
    let authenticated_url = format!("http://admin:admin@localhost:{port}/");
    let start = || {
        let mut command = ram_command(tmpdir.path(), port);
        command.args(["--auth", TEST_AUTH_RULE, "-A"]);
        ServerProc::spawn(command)
    };

    let first = start();
    let old = listing_mutation_version(&format!("{authenticated_url}?json"))?;
    drop(first);

    let _second = start();
    let current = listing_mutation_version(&format!("{authenticated_url}?json"))?;
    assert_ne!(
        old, current,
        "each server process needs a unique boot identity"
    );
    let rejected = reqwest::blocking::Client::new()
        .delete(format!("{authenticated_url}test.html"))
        .header("X-Ram-If-Mutation-Version", old)
        .send()?;
    assert_eq!(rejected.status(), 412);
    assert!(tmpdir.path().join("test.html").is_file());
    Ok(())
}

/// 静态禁用的写方法必须在正文、Destination 和变更锁之前返回 403。拒绝请求不是最终文件
/// 系统事务，不得推进 revision；否则只读认证方可以用无副作用请求让所有列表操作永久 412。
/// Statically disabled writes must return 403 before bodies, Destination parsing, and mutation locks.
/// A rejected request is not a final filesystem transaction and must not advance the revision, or a
/// read-only principal could force every listing action into a permanent stream of 412 responses.
#[rstest]
fn configuration_denied_mutations_leave_listing_version_unchanged(
    server: TestServer,
) -> Result<(), Error> {
    for method in [
        &b"PUT"[..],
        &b"PATCH"[..],
        &b"DELETE"[..],
        &b"MKCOL"[..],
        &b"COPY"[..],
        &b"MOVE"[..],
    ] {
        let before = listing_mutation_version(&format!("{}?json", server.url()))?;
        let response = reqwest::blocking::Client::new()
            .request(
                reqwest::Method::from_bytes(method)?,
                format!("{}test.html", server.url()),
            )
            .body("a disabled write body must not be staged")
            .send()?;
        assert_eq!(
            response.status(),
            403,
            "{} must be rejected by its static capability gate",
            String::from_utf8_lossy(method)
        );
        let after = listing_mutation_version(&format!("{}?json", server.url()))?;
        assert_eq!(
            after,
            before,
            "{} advanced the mutation revision despite a static 403",
            String::from_utf8_lossy(method)
        );
    }
    Ok(())
}

/// 单独启用上传也不能让禁用删除的 DELETE 进入变更事务。
/// Enabling uploads alone must not let a delete-disabled DELETE enter a mutation transaction.
#[rstest]
fn delete_disabled_with_upload_enabled_preserves_listing_version(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    let before = listing_mutation_version(&format!("{}?json", server.url()))?;
    let response = fetch!(b"DELETE", format!("{}test.html", server.url())).send()?;
    assert_eq!(response.status(), 403);
    let after = listing_mutation_version(&format!("{}?json", server.url()))?;
    assert_eq!(after, before);
    assert!(server.path().join("test.html").is_file());
    Ok(())
}

#[rstest]
fn copy_rejects_duplicate_host_fields(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let mut headers = reqwest::header::HeaderMap::new();
    headers.append("host", format!("localhost:{}", server.port()).parse()?);
    headers.append("host", "other.invalid".parse()?);
    let response = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header(
            "destination",
            format!("{}duplicate-host.html", server.url()),
        )
        .headers(headers)
        .send()?;
    assert_eq!(response.status(), 400);
    assert!(!server.path().join("duplicate-host.html").exists());
    Ok(())
}

#[rstest]
fn copy_does_not_preserve_special_mode_bits(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let source = server.path().join("privileged-source.bin");
    std::fs::write(&source, b"source")?;
    let mut permissions = std::fs::metadata(&source)?.permissions();
    permissions.set_mode(0o6755);
    std::fs::set_permissions(&source, permissions)?;

    let destination_url = format!("{}ordinary-copy.bin", server.url());
    let resp = fetch!(b"COPY", format!("{}privileged-source.bin", server.url()))
        .header("Destination", &destination_url)
        .send()?;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        std::fs::metadata(server.path().join("ordinary-copy.bin"))?.mode() & 0o7000,
        0
    );
    Ok(())
}

#[rstest]
fn copy_size_limit_is_checked_before_staging(
    #[with(&["-A", "--max-copy-size", "8"])] server: TestServer,
) -> Result<(), Error> {
    std::fs::write(server.path().join("eight.bin"), b"12345678")?;
    let exact_dest = format!("{}eight-copy.bin", server.url());
    let resp = fetch!(b"COPY", format!("{}eight.bin", server.url()))
        .header("Destination", &exact_dest)
        .send()?;
    assert_eq!(resp.status(), 201);
    assert_eq!(
        std::fs::read(server.path().join("eight-copy.bin"))?,
        b"12345678"
    );

    std::fs::write(server.path().join("nine.bin"), b"123456789")?;
    let oversized_dest = format!("{}nine-copy.bin", server.url());
    let resp = fetch!(b"COPY", format!("{}nine.bin", server.url()))
        .header("Destination", &oversized_dest)
        .send()?;
    assert_eq!(resp.status(), 507);
    assert!(!server.path().join("nine-copy.bin").exists());
    Ok(())
}

#[rstest]
fn copy_overwrite_requires_allow_delete(
    #[with(&["--allow-upload"])] server: TestServer,
) -> Result<(), Error> {
    // test.txt 已存在；覆盖等价于删除旧内容，因此仅 allow_upload 不足。
    // test.txt exists; overwriting deletes old content, so allow_upload alone is insufficient.
    let new_url = format!("{}test.txt", server.url());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn copy_overwrite_allowed_with_allow_delete(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let new_url = format!("{}test.txt", server.url());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 204);
    Ok(())
}

#[rstest]
fn copy_preserves_source_ordinary_mode_and_strips_special_bits(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let source = server.path().join("copy-mode-source.bin");
    let destination = server.path().join("copy-mode-destination.bin");
    std::fs::write(&source, b"source")?;
    std::fs::set_permissions(&source, std::fs::Permissions::from_mode(0o6751))?;
    std::fs::write(&destination, b"old destination")?;
    std::fs::set_permissions(&destination, std::fs::Permissions::from_mode(0o600))?;

    let response = fetch!(b"COPY", format!("{}copy-mode-source.bin", server.url()))
        .header(
            "Destination",
            format!("{}copy-mode-destination.bin", server.url()),
        )
        .header("Overwrite", "T")
        .send()?;
    assert_eq!(response.status(), 204);
    assert_eq!(std::fs::read(&destination)?, b"source");
    assert_eq!(std::fs::metadata(destination)?.mode() & 0o7777, 0o751);
    Ok(())
}

#[rstest]
fn copy_file_cannot_replace_collection_and_never_leaks_commit_500(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let destination = format!("{}dir1/", server.url());
    let response = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", destination)
        .header("Overwrite", "T")
        .send()?;
    assert_eq!(response.status(), 409);
    assert!(server.path().join("dir1").is_dir());
    assert!(server.path().join("dir1/test.html").is_file());
    Ok(())
}

#[rstest]
fn copy_overwrite_f_is_rejected(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test.txt", server.url());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .header("Overwrite", "F")
        .send()?;
    assert_eq!(resp.status(), 412);
    Ok(())
}

#[rstest]
fn copy_source_only_requires_read(
    #[with(&["--auth", "user:pass@/:rw,/dir1:ro", "-A"])] server: TestServer,
) -> Result<(), Error> {
    // dir1 对此用户只读；COPY 只读取源而不写入，因此不得禁止只读源。
    // dir1 is read-only; COPY only reads the source, so a read-only source must be allowed.
    let new_url = format!("{}test-from-dir1.html", server.url());
    let resp = fetch!(b"COPY", format!("{}dir1/test.html", server.url()))
        .header("Destination", &new_url)
        .basic_auth("user", Some("pass"))
        .send()?;
    assert_eq!(resp.status(), 201);
    Ok(())
}

#[rstest]
fn copy_not_allow_upload(server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn copy_file_404(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"COPY", format!("{}404", server.url()))
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn move_file(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let origin_url = format!("{}test.html", server.url());
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"MOVE", &origin_url)
        .header("Destination", &new_url)
        .send()?;
    // 新目标是创建而非覆盖。 / A new destination is a creation, not an overwrite.
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(new_url)?;
    assert_eq!(resp.status(), 200);
    let resp = reqwest::blocking::get(origin_url)?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn move_overwrite_f_is_rejected(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test.txt", server.url());
    let resp = fetch!(b"MOVE", format!("{}test.html", server.url()))
        .header("Destination", &new_url)
        .header("Overwrite", "F")
        .send()?;
    assert_eq!(resp.status(), 412);
    // MOVE 被拒时源必须保持不变。 / The source must remain untouched when MOVE is rejected.
    let resp = reqwest::blocking::get(format!("{}test.html", server.url()))?;
    assert_eq!(resp.status(), 200);
    Ok(())
}

#[rstest]
fn move_not_allow_upload(#[with(&["--allow-delete"])] server: TestServer) -> Result<(), Error> {
    let origin_url = format!("{}test.html", server.url());
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"MOVE", &origin_url)
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn move_not_allow_delete(#[with(&["--allow-upload"])] server: TestServer) -> Result<(), Error> {
    let origin_url = format!("{}test.html", server.url());
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"MOVE", &origin_url)
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 403);
    Ok(())
}

#[rstest]
fn move_file_404(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let new_url = format!("{}test2.html", server.url());
    let resp = fetch!(b"MOVE", format!("{}404", server.url()))
        .header("Destination", &new_url)
        .send()?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
#[case(b"LOCK")]
#[case(b"UNLOCK")]
fn unsupported_lock_methods_are_not_falsely_advertised(
    #[case] method: &[u8],
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let resp = reqwest::blocking::Client::new()
        .request(
            reqwest::Method::from_bytes(method)?,
            format!("{}test.html", server.url()),
        )
        .send()?;
    assert_eq!(resp.status(), 405);
    let allow = resp.headers().get("allow").unwrap().to_str()?;
    assert!(!allow.contains("LOCK"));
    assert!(!allow.contains("UNLOCK"));
    Ok(())
}

/// 固定服务根虽是集合，但在能力内没有可变父目录项。OPTIONS 不得声明 DELETE/MOVE，根源
/// 操作必须在解析其他请求头前失败，把根作为发布目标也不能落入 500。
/// The pinned service root is a collection but has no mutable parent entry inside the capability.
/// OPTIONS must not advertise DELETE/MOVE, those source operations must fail before parsing other
/// headers, and using the root as a publication destination must not fall through to a 500.
#[rstest]
fn served_root_is_not_a_mutation_endpoint(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let options = fetch!(b"OPTIONS", server.url()).send()?;
    assert_eq!(options.status(), 200);
    let allow = options.headers().get("allow").unwrap().to_str()?;
    assert!(!allow.split(", ").any(|method| method == "DELETE"));
    assert!(!allow.split(", ").any(|method| method == "MOVE"));

    let delete = fetch!(b"DELETE", server.url()).send()?;
    assert_eq!(delete.status(), 403);
    let move_root = fetch!(b"MOVE", server.url()).send()?;
    assert_eq!(move_root.status(), 403);

    let copy_to_root = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", server.url().as_str())
        .send()?;
    assert_eq!(copy_to_root.status(), 403);
    assert_eq!(
        reqwest::blocking::get(format!("{}test.html", server.url()))?.status(),
        200
    );
    Ok(())
}

/// 特殊命名空间节点没有可读的 HTTP/DAV 表示；GET/HEAD/PROPFIND 仍是可路由查找并统一
/// 返回 404，属性变更才是 405。Allow 与实际分派表一致，同时保留 DELETE/MOVE 命名空间操作。
/// A special namespace node has no readable HTTP/DAV representation. GET/HEAD/PROPFIND remain
/// routable lookups that uniformly return 404; property mutation is the unsupported 405 case. Allow
/// stays aligned with the dispatch table while retaining DELETE/MOVE namespace operations.
#[rstest]
fn special_node_capabilities_match_actual_routes(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let source_path = server.path().join("special.pipe");
    rustix::fs::mkfifoat(
        rustix::fs::CWD,
        &source_path,
        rustix::fs::Mode::from_raw_mode(0o600),
    )?;
    let source = format!("{}special.pipe", server.url());
    let expected = "GET, HEAD, OPTIONS, DELETE, PROPFIND, MOVE, CHECKAUTH, LOGOUT";

    let options = fetch!(b"OPTIONS", &source).send()?;
    assert_eq!(options.status(), 200);
    assert_eq!(options.headers().get("allow").unwrap(), expected);

    for method in [b"GET".as_slice(), b"HEAD", b"PROPFIND"] {
        let response = reqwest::blocking::Client::new()
            .request(reqwest::Method::from_bytes(method)?, &source)
            .send()?;
        assert_eq!(
            response.status(),
            404,
            "{}",
            String::from_utf8_lossy(method)
        );
        assert!(response.headers().get("allow").is_none());
    }

    let proppatch = fetch!(b"PROPPATCH", &source).send()?;
    assert_eq!(proppatch.status(), 405);
    assert_eq!(proppatch.headers().get("allow").unwrap(), expected);

    let moved_path = server.path().join("moved.pipe");
    let moved = format!("{}moved.pipe", server.url());
    let response = fetch!(b"MOVE", &source)
        .header("destination", &moved)
        .send()?;
    assert_eq!(response.status(), 201);
    assert!(!source_path.exists());
    assert!(
        std::fs::symlink_metadata(&moved_path)?
            .file_type()
            .is_fifo()
    );

    let response = fetch!(b"DELETE", &moved).send()?;
    assert_eq!(response.status(), 204);
    assert!(!moved_path.exists());
    Ok(())
}

/// 把集合移动到自身后代是 WebDAV 命名空间冲突；必须在 rename(2) 前拒绝，否则 EINVAL 会被
/// 误分类为内部 I/O 故障。
/// Moving a collection below itself is a WebDAV namespace conflict. Reject it before rename(2),
/// whose EINVAL would otherwise be classified as an internal I/O failure.
#[rstest]
fn move_collection_into_its_descendant_is_conflict_without_side_effects(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    std::fs::create_dir(server.path().join("dir1/child"))?;
    let source = format!("{}dir1", server.url());
    let destination = format!("{}dir1/child/moved", server.url());
    let response = fetch!(b"MOVE", &source)
        .header("Destination", &destination)
        .send()?;
    assert_eq!(response.status(), 409);
    assert!(server.path().join("dir1").is_dir());
    assert!(server.path().join("dir1/child").is_dir());
    assert!(!server.path().join("dir1/child/moved").exists());
    Ok(())
}

#[rstest]
fn options_and_405_share_target_acl_and_feature_capabilities(
    #[with(&[
        "-A",
        "--auth",
        "reader:pass@/:ro",
        "--auth",
        "writer:pass@/:rw",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let file_url = format!("{}test.html", server.url());

    let anonymous = client.request(reqwest::Method::OPTIONS, &file_url).send()?;
    assert_eq!(anonymous.status(), 200);
    assert_eq!(
        anonymous.headers().get("allow").unwrap(),
        "GET, HEAD, OPTIONS, PROPFIND, CHECKAUTH, LOGOUT"
    );
    assert!(!anonymous.headers().contains_key("dav"));

    let reader = client
        .request(reqwest::Method::OPTIONS, &file_url)
        .basic_auth("reader", Some("pass"))
        .send()?;
    assert_eq!(reader.status(), 200);
    assert_eq!(
        reader.headers().get("allow"),
        anonymous.headers().get("allow")
    );

    let writer = client
        .request(reqwest::Method::OPTIONS, &file_url)
        .basic_auth("writer", Some("pass"))
        .send()?;
    assert_eq!(writer.status(), 200);
    let writer_file_allow = writer.headers().get("allow").unwrap().to_str()?;
    assert_eq!(
        writer_file_allow,
        "GET, HEAD, OPTIONS, PUT, DELETE, PATCH, PROPFIND, PROPPATCH, COPY, MOVE, CHECKAUTH, LOGOUT"
    );
    assert!(!writer_file_allow.contains("MKCOL"));

    let writer_collection = client
        .request(reqwest::Method::OPTIONS, format!("{}dir1", server.url()))
        .basic_auth("writer", Some("pass"))
        .send()?;
    assert_eq!(
        writer_collection.headers().get("allow").unwrap(),
        "GET, HEAD, OPTIONS, DELETE, PROPFIND, PROPPATCH, MOVE, CHECKAUTH, LOGOUT"
    );

    let writer_missing = client
        .request(
            reqwest::Method::OPTIONS,
            format!("{}not-created", server.url()),
        )
        .basic_auth("writer", Some("pass"))
        .send()?;
    assert_eq!(
        writer_missing.headers().get("allow").unwrap(),
        "GET, HEAD, OPTIONS, PUT, PROPFIND, MKCOL, CHECKAUTH, LOGOUT"
    );

    let unsupported = client
        .request(reqwest::Method::from_bytes(b"BREW")?, &file_url)
        .basic_auth("writer", Some("pass"))
        .send()?;
    assert_eq!(unsupported.status(), 405);
    assert_eq!(
        unsupported.headers().get("allow").unwrap(),
        writer_file_allow
    );
    assert!(!unsupported.headers().contains_key("dav"));
    Ok(())
}

/// `Destination` 指名另一台主机时必须拒绝：客户端说"复制到别的主机"，
/// 服务器却默默在本机操作，至少是误导行为。
/// Reject a `Destination` naming another host: silently performing the operation locally when the
/// client requested a remote host would at minimum be misleading.
#[rstest]
fn copy_dest_foreign_host_rejected(#[with(&["-A"])] server: TestServer) -> Result<(), Error> {
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", "http://evil.example.com/test2.html")
        .send()?;
    assert_eq!(resp.status(), 400);
    // 目标文件不应被创建。 / The destination file must not be created.
    let resp = reqwest::blocking::get(format!("{}test2.html", server.url()))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

/// Destination URI 携带 userinfo（`user:pass@host`）时，主机比较必须
/// 剥掉 userinfo 再比——它仍然指向本服务器，应当放行。
/// When a Destination URI contains userinfo (`user:pass@host`), strip it before comparing hosts;
/// the URI still targets this server and must be accepted.
#[rstest]
fn copy_dest_userinfo_is_ignored_for_host_check(
    #[with(&["-A"])] server: TestServer,
) -> Result<(), Error> {
    let dest = format!("http://user:pass@localhost:{}/test2.html", server.port());
    let resp = fetch!(b"COPY", format!("{}test.html", server.url()))
        .header("Destination", &dest)
        .send()?;
    assert_eq!(resp.status(), 201);
    let resp = reqwest::blocking::get(format!("{}test2.html", server.url()))?;
    assert_eq!(resp.status(), 200);
    Ok(())
}
