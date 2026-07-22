#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{BIN_FILE, DIR_NO_FOUND, DIR_NO_INDEX, Error, FILES, TestServer, server};
use rstest::rstest;

fn assert_management_ui_csp(value: &reqwest::header::HeaderValue) -> Result<(), Error> {
    let policy = value.to_str()?;
    for directive in [
        "default-src 'none'",
        "script-src 'self'",
        "style-src 'self'",
        "connect-src 'self'",
        "frame-src blob:",
        "object-src 'none'",
        "base-uri 'none'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ] {
        assert!(
            policy.contains(directive),
            "missing CSP directive: {directive}"
        );
    }
    assert!(!policy.contains("'unsafe-inline'"));
    assert!(!policy.contains("'unsafe-eval'"));
    assert!(!policy.contains("frame-src 'self'"));
    Ok(())
}

#[rstest]
fn management_pages_have_strict_csp(server: TestServer) -> Result<(), Error> {
    let listing = reqwest::blocking::get(server.url())?;
    assert_management_ui_csp(
        listing
            .headers()
            .get("content-security-policy")
            .expect("directory management page must have CSP"),
    )?;
    assert_eq!(
        listing.headers().get("permissions-policy").unwrap(),
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    );

    let editor = reqwest::blocking::get(format!("{}test.txt?edit", server.url()))?;
    assert_management_ui_csp(
        editor
            .headers()
            .get("content-security-policy")
            .expect("editor management page must have CSP"),
    )?;
    assert_eq!(
        editor.headers().get("permissions-policy").unwrap(),
        "camera=(), geolocation=(), microphone=(), payment=(), usb=()"
    );
    Ok(())
}

#[rstest]
fn render_index(#[with(&["--render-index"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert!(
        resp.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()?
            .starts_with("inline;")
    );
    assert!(!resp.headers().contains_key("content-security-policy"));
    let text = resp.text()?;
    assert_eq!(text, "This is index.html");
    Ok(())
}

#[rstest]
fn render_index2(#[with(&["--render-index"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), DIR_NO_INDEX))?;
    assert_eq!(resp.status(), 404);
    Ok(())
}

#[rstest]
fn render_try_index(#[with(&["--render-try-index"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    let text = resp.text()?;
    assert_eq!(text, "This is index.html");
    Ok(())
}

#[rstest]
fn render_try_index2(#[with(&["--render-try-index"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), DIR_NO_INDEX))?;
    let files: Vec<&str> = FILES
        .iter()
        .filter(|v| **v != "index.html")
        .cloned()
        .collect();
    assert_resp_paths!(resp, files);
    Ok(())
}

#[rstest]
fn render_try_index3(
    #[with(&["--render-try-index", "--allow-archive"])] server: TestServer,
) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}?zip", server.url(), DIR_NO_INDEX))?;
    assert_eq!(resp.status(), 200);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/zip"
    );
    Ok(())
}

#[rstest]
#[case(server(&["--render-try-index"] as &[&str]), false)]
#[case(server(&["--render-try-index", "--allow-search"] as &[&str]), true)]
fn render_try_index4(#[case] server: TestServer, #[case] searched: bool) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}?q={}", server.url(), DIR_NO_INDEX, BIN_FILE))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert_eq!(paths.iter().all(|v| v.contains(BIN_FILE)), searched);
    Ok(())
}

#[rstest]
fn render_spa(#[with(&["--render-spa"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    let text = resp.text()?;
    assert_eq!(text, "This is index.html");
    Ok(())
}

#[rstest]
fn render_spa2(#[with(&["--render-spa"])] server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), DIR_NO_FOUND))?;
    let text = resp.text()?;
    assert_eq!(text, "This is index.html");
    Ok(())
}

#[rstest]
fn untrusted_html_downloads_by_default_with_sandbox(server: TestServer) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}index.html", server.url()))?;
    assert!(
        resp.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()?
            .starts_with("attachment;")
    );
    assert!(
        resp.headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()?
            .starts_with("sandbox;")
    );
    Ok(())
}

#[rstest]
fn render_mode_only_trusts_selected_index_entrypoint(
    #[with(&[
        "--render-index",
        "--allow-upload",
        "--allow-active-content-risk",
    ])]
    server: TestServer,
) -> Result<(), Error> {
    let trusted = reqwest::blocking::get(server.url())?;
    assert!(
        trusted
            .headers()
            .get("content-disposition")
            .unwrap()
            .to_str()?
            .starts_with("inline;")
    );
    assert!(!trusted.headers().contains_key("content-security-policy"));

    std::fs::write(
        server.path().join("uploaded.html"),
        b"<script>document.title='untrusted'</script>",
    )?;
    let resp = reqwest::blocking::get(format!("{}uploaded.html", server.url()))?;
    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-disposition")
            .unwrap()
            .to_str()?
            .starts_with("attachment;")
    );
    assert!(
        resp.headers()
            .get("content-security-policy")
            .unwrap()
            .to_str()?
            .starts_with("sandbox;")
    );
    Ok(())
}

#[rstest]
fn dynamic_directory_head_omits_length_without_scanning(server: TestServer) -> Result<(), Error> {
    let get = fetch!(b"GET", server.url()).send()?;
    let head = fetch!(b"HEAD", server.url()).send()?;
    assert_eq!(get.status(), 200);
    assert_eq!(head.status(), 200);
    assert!(get.headers().contains_key("content-length"));
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}

#[rstest]
fn search_head_does_not_claim_an_incorrect_dynamic_length(
    #[with(&["--allow-search"])] server: TestServer,
) -> Result<(), Error> {
    let head = fetch!(b"HEAD", format!("{}?q=test", server.url())).send()?;
    assert_eq!(head.status(), 200);
    assert!(!head.headers().contains_key("content-length"));
    assert!(head.bytes()?.is_empty());
    Ok(())
}
