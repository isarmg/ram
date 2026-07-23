#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/utils.rs"]
mod utils;

use fixtures::{Error, TestServer, server};
use rstest::rstest;

#[rstest]
fn ls_dir_sort_by_name(server: TestServer) -> Result<(), Error> {
    let url = server.url();
    let resp = reqwest::blocking::get(format!("{url}?sort=name&order=asc"))?;
    let paths1 = self::utils::retrieve_index_paths(&resp.text()?);
    let resp = reqwest::blocking::get(format!("{url}?sort=name&order=desc"))?;
    let mut paths2 = self::utils::retrieve_index_paths(&resp.text()?);
    paths2.reverse();
    assert_eq!(paths1, paths2);
    Ok(())
}

#[rstest]
fn search_dir_sort_by_name(#[with(&["--allow-search"])] server: TestServer) -> Result<(), Error> {
    const QUERY: &str = "test.html";

    let url = server.url();
    let resp = reqwest::blocking::get(format!("{url}?q={QUERY}&sort=name&order=asc"))?;
    assert_eq!(resp.status(), 200);
    let paths1 = self::utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths1.is_empty());
    assert!(paths1.iter().all(|path| path.contains(QUERY)));

    let resp = reqwest::blocking::get(format!("{url}?q={QUERY}&sort=name&order=desc"))?;
    assert_eq!(resp.status(), 200);
    let mut paths2 = self::utils::retrieve_index_paths(&resp.text()?);
    assert!(!paths2.is_empty());
    assert!(paths2.iter().all(|path| path.contains(QUERY)));

    paths2.reverse();
    assert_eq!(paths1, paths2);
    Ok(())
}
