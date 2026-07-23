#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, TestServer, server};
use rstest::rstest;

#[rstest]
#[case(server(&[] as &[&str]), true)]
#[case(server(&["--hidden", ".git,index.html"]), false)]
fn hidden_get_dir(#[case] server: TestServer, #[case] exist: bool) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(paths.contains("dir1/"));
    assert_eq!(paths.contains(".git/"), exist);
    assert_eq!(paths.contains("index.html"), exist);
    Ok(())
}

#[rstest]
#[case(server(&[] as &[&str]), true)]
#[case(server(&["--hidden", "*.html"]), false)]
fn hidden_get_dir2(#[case] server: TestServer, #[case] exist: bool) -> Result<(), Error> {
    let resp = reqwest::blocking::get(server.url())?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert!(paths.contains("dir1/"));
    assert_eq!(paths.contains("index.html"), exist);
    assert_eq!(paths.contains("test.html"), exist);
    Ok(())
}

#[rstest]
#[case(server(&["--allow-search"] as &[&str]), true)]
#[case(server(&["--allow-search", "--hidden", ".git,test.html"]), false)]
fn hidden_search_dir(#[case] server: TestServer, #[case] exist: bool) -> Result<(), Error> {
    const QUERY: &str = "test.html";

    let resp = reqwest::blocking::get(format!("{}?q={QUERY}", server.url()))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);

    if exist {
        assert!(!paths.is_empty());
        assert!(paths.iter().all(|path| path.contains(QUERY)));
    } else {
        assert!(paths.is_empty() || paths.iter().all(|path| !path.contains(QUERY)));
    }
    Ok(())
}

#[rstest]
#[case(server(&["--hidden", "hidden/"]), "dir4/", 1)]
#[case(server(&["--hidden", "hidden"]), "dir4/", 0)]
fn hidden_dir_only(
    #[case] server: TestServer,
    #[case] dir: &str,
    #[case] count: usize,
) -> Result<(), Error> {
    let resp = reqwest::blocking::get(format!("{}{}", server.url(), dir))?;
    assert_eq!(resp.status(), 200);
    let paths = utils::retrieve_index_paths(&resp.text()?);
    assert_eq!(paths.len(), count);
    Ok(())
}
