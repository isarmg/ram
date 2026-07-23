#[path = "common/fixtures.rs"]
mod fixtures;

use fixtures::{Error, TestServer, server};
use hyper::StatusCode;
use rstest::rstest;

const ORIGIN: &str = "https://app.example";

fn preflight(
    server: &TestServer,
    path: &str,
    method: &str,
    headers: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    let client = reqwest::blocking::Client::new();
    let mut request = client
        .request(reqwest::Method::OPTIONS, format!("{}{path}", server.url()))
        .header("Origin", ORIGIN)
        .header("Access-Control-Request-Method", method);
    if let Some(headers) = headers {
        request = request.header("Access-Control-Request-Headers", headers);
    }
    request
}

#[rstest]
fn cors_is_disabled_by_default(server: TestServer) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let response = client.get(server.url()).header("Origin", ORIGIN).send()?;
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[rstest]
fn wildcard_simple_response_never_enables_credentials(
    #[with(&["--enable-cors"])] server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let response = client.get(server.url()).header("Origin", ORIGIN).send()?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        "*"
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    assert!(
        response
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()?
            .contains("Content-Range")
    );
    assert!(
        response
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()?
            .contains("X-Ram-List-Omitted")
    );
    assert!(
        response
            .headers()
            .get("access-control-expose-headers")
            .unwrap()
            .to_str()?
            .contains("X-Ram-Mutation-Version")
    );
    assert!(response.headers().get_all("vary").iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|value| value.eq_ignore_ascii_case("Origin"))
    }));
    // 仅真实 Origin 请求发送 CORS 响应字段。 / CORS response fields are emitted only for a real Origin request.
    let same_origin = reqwest::blocking::get(server.url())?;
    assert!(
        !same_origin
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[rstest]
fn default_cors_policy_allows_listing_mutation_condition(
    #[with(&["-A", "--enable-cors"])] server: TestServer,
) -> Result<(), Error> {
    let response = preflight(
        &server,
        "test.html",
        "DELETE",
        Some("X-Ram-If-Mutation-Version"),
    )
    .send()?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-headers")
            .unwrap(),
        "x-ram-if-mutation-version"
    );
    Ok(())
}

#[rstest]
fn exact_origin_allowlist_is_not_reflective(
    #[with(&[
        "--enable-cors",
        "--cors-origins",
        "https://app.example,https://second.example:8443",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let client = reqwest::blocking::Client::new();
    let accepted = client.get(server.url()).header("Origin", ORIGIN).send()?;
    assert_eq!(
        accepted
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        ORIGIN
    );

    let rejected = client
        .get(server.url())
        .header("Origin", "https://attacker.example")
        .send()?;
    assert!(
        !rejected
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[rstest]
fn preflight_intersects_configuration_target_and_global_features(
    #[with(&[
        "-A",
        "--enable-cors",
        "--cors-origins",
        "https://app.example",
        "--cors-methods",
        "GET,PUT,MKCOL,PROPFIND",
        "--cors-headers",
        "Authorization,Content-Type,Depth",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let response = preflight(
        &server,
        "test.html",
        "PUT",
        Some("Authorization, Content-Type"),
    )
    .send()?;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .unwrap(),
        ORIGIN
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-methods")
            .unwrap(),
        "GET, PUT, PROPFIND"
    );
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-headers")
            .unwrap(),
        "authorization, content-type"
    );
    assert!(
        !response
            .headers()
            .contains_key("access-control-allow-credentials")
    );
    for field in [
        "Origin",
        "Access-Control-Request-Method",
        "Access-Control-Request-Headers",
    ] {
        assert!(response.headers().get_all("vary").iter().any(|value| {
            value
                .to_str()
                .is_ok_and(|value| value.eq_ignore_ascii_case(field))
        }));
    }
    assert!(
        response
            .headers()
            .get("cache-control")
            .unwrap()
            .to_str()?
            .contains("no-store")
    );

    // MKCOL 位于运维允许列表，但不适用于现有集合；单次能力计算收窄预检。
    // MKCOL is operator-allowed but inapplicable to an existing collection; one capability calculation narrows preflight.
    let wrong_target = preflight(&server, "dir1", "MKCOL", None).send()?;
    assert_eq!(wrong_target.status(), StatusCode::FORBIDDEN);
    assert!(
        !wrong_target
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[rstest]
fn preflight_rejects_disabled_method_unlisted_header_and_origin(
    #[with(&[
        "--enable-cors",
        "--cors-origins",
        "https://app.example",
        "--cors-methods",
        "GET,PUT",
        "--cors-headers",
        "Content-Type",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    // PUT 已为 CORS 配置，但全局上传功能关闭。 / PUT is configured for CORS while global upload is disabled.
    let disabled = preflight(&server, "new.txt", "PUT", Some("Content-Type")).send()?;
    assert_eq!(disabled.status(), StatusCode::FORBIDDEN);

    let bad_header = preflight(&server, "test.html", "GET", Some("X-Not-Allowed")).send()?;
    assert_eq!(bad_header.status(), StatusCode::FORBIDDEN);

    let client = reqwest::blocking::Client::new();
    let bad_origin = client
        .request(reqwest::Method::OPTIONS, server.url())
        .header("Origin", "https://attacker.example")
        .header("Access-Control-Request-Method", "GET")
        .send()?;
    assert_eq!(bad_origin.status(), StatusCode::FORBIDDEN);
    assert!(
        !bad_origin
            .headers()
            .contains_key("access-control-allow-origin")
    );
    Ok(())
}

#[rstest]
fn malformed_preflight_is_rejected_without_reflection(
    #[with(&["--enable-cors"])] server: TestServer,
) -> Result<(), Error> {
    let unknown_method = preflight(&server, "test.html", "BREW", None).send()?;
    assert_eq!(unknown_method.status(), StatusCode::FORBIDDEN);

    let empty_header =
        preflight(&server, "test.html", "GET", Some("Content-Type,,Depth")).send()?;
    assert_eq!(empty_header.status(), StatusCode::BAD_REQUEST);
    assert!(
        !empty_header
            .headers()
            .contains_key("access-control-allow-headers")
    );
    Ok(())
}
