use super::*;
use http_body_util::BodyExt;

fn limits_with_properties(max_properties: usize) -> DavLimits {
    DavLimits {
        max_properties,
        ..DavLimits::hard_maximum()
    }
}

#[test]
fn href_preserves_the_preencoded_uri_prefix_and_encodes_only_the_item_path() {
    let item = PathItem {
        path_type: PathType::File,
        name: "dir/文件 & %.txt".to_string(),
        mtime: 0,
        size: 0,
        size_known: true,
    };
    assert_eq!(
        render_href(&item, "/cap/%E5%89%8D%20prefix/"),
        "/cap/%E5%89%8D%20prefix/dir/%E6%96%87%E4%BB%B6%20%26%20%25.txt"
    );
}

fn assert_request_budget(error: DavRequestError, expected: DavBudgetExceeded) {
    match error {
        DavRequestError::BudgetExceeded(actual) => assert_eq!(actual, expected),
        other => panic!("expected a WebDAV request budget error, got {other:?}"),
    }
}

fn assert_response_budget(error: DavResponseError, expected: DavBudgetExceeded) {
    match error {
        DavResponseError::BudgetExceeded(actual) => assert_eq!(actual, expected),
    }
}

#[test]
fn propfind_complexity_accepts_exact_limit_and_rejects_one_more() {
    let limits = DavLimits::hard_maximum();
    assert!(ensure_propfind_complexity(1024, 64, limits).is_ok());
    assert_response_budget(
        ensure_propfind_complexity(1025, 64, limits).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavRenderedProperties,
            limits.max_rendered_properties as u64,
            Some(65_600),
        ),
    );
    assert_response_budget(
        ensure_propfind_complexity(usize::MAX, 2, limits).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavRenderedProperties,
            limits.max_rendered_properties as u64,
            None,
        ),
    );
}

#[test]
fn request_property_count_budget_reports_configured_limit_and_observed_count() {
    let xml = br#"
            <D:propfind xmlns:D="DAV:" xmlns:X="urn:test">
              <D:prop><X:first/><X:second/></D:prop>
            </D:propfind>
        "#;
    assert_request_budget(
        parse_propfind_body(xml, limits_with_properties(1)).unwrap_err(),
        DavBudgetExceeded::new(AdmissionResource::WebDavProperties, 1, Some(2)),
    );
}

#[test]
fn aggregate_property_name_budget_reports_exact_crossing() {
    let limits = DavLimits::hard_maximum();
    let mut budget = DavPropertyBudget::new(limits);
    let bytes_per_property = DAV_MAX_NAMESPACE_BYTES + DAV_MAX_LOCAL_NAME_BYTES;
    let accepted = DAV_MAX_PROPERTY_NAME_BYTES / bytes_per_property;
    for index in 0..accepted {
        let suffix = index.to_string();
        let property = DavProperty {
            namespace: Arc::from("n".repeat(DAV_MAX_NAMESPACE_BYTES)),
            local_name: Arc::from(format!(
                "{}{}",
                "p".repeat(DAV_MAX_LOCAL_NAME_BYTES - suffix.len()),
                suffix
            )),
        };
        assert!(budget.insert_unique(&property).unwrap());
    }
    let property = DavProperty {
        namespace: Arc::from("n".repeat(DAV_MAX_NAMESPACE_BYTES)),
        local_name: Arc::from("p".repeat(DAV_MAX_LOCAL_NAME_BYTES)),
    };
    assert_request_budget(
        budget.insert_unique(&property).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavPropertyNameBytes,
            DAV_MAX_PROPERTY_NAME_BYTES as u64,
            Some(((accepted + 1) * bytes_per_property) as u64),
        ),
    );
}

#[test]
fn xml_name_budgets_distinguish_namespace_and_local_name() {
    let long_namespace = "n".repeat(DAV_MAX_NAMESPACE_BYTES + 1);
    let xml = format!("<D:propfind xmlns:D=\"{long_namespace}\"/>");
    assert_request_budget(
        parse_xml(xml.as_bytes()).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavNamespaceBytes,
            DAV_MAX_NAMESPACE_BYTES as u64,
            Some((DAV_MAX_NAMESPACE_BYTES + 1) as u64),
        ),
    );

    let long_local_name = "n".repeat(DAV_MAX_LOCAL_NAME_BYTES + 1);
    let xml = format!("<{long_local_name}/>");
    assert_request_budget(
        parse_xml(xml.as_bytes()).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavLocalNameBytes,
            DAV_MAX_LOCAL_NAME_BYTES as u64,
            Some((DAV_MAX_LOCAL_NAME_BYTES + 1) as u64),
        ),
    );
}

#[test]
fn xml_complexity_budgets_report_exact_resource_and_observed_value() {
    let mut too_many_elements = String::from("<root>");
    too_many_elements.push_str(&"<node/>".repeat(DAV_XML_MAX_ELEMENTS));
    too_many_elements.push_str("</root>");
    assert_request_budget(
        parse_xml(too_many_elements.as_bytes()).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavXmlElements,
            DAV_XML_MAX_ELEMENTS as u64,
            Some((DAV_XML_MAX_ELEMENTS + 1) as u64),
        ),
    );

    let deeply_nested = format!(
        "{}{}",
        "<node>".repeat(DAV_XML_MAX_DEPTH + 1),
        "</node>".repeat(DAV_XML_MAX_DEPTH + 1)
    );
    assert_request_budget(
        parse_xml(deeply_nested.as_bytes()).unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavXmlDepth,
            DAV_XML_MAX_DEPTH as u64,
            Some((DAV_XML_MAX_DEPTH + 1) as u64),
        ),
    );
}

#[test]
fn depth_one_retained_items_have_a_derived_hard_upper_bound() {
    let limits = DavLimits::hard_maximum();
    for property_count in 1..=limits.max_properties {
        let child_probe = propfind_child_probe_limit(limits, property_count);
        assert!(
            ensure_propfind_complexity(child_probe, property_count, limits).is_ok(),
            "the last representable total item count must fit"
        );
        assert!(
            ensure_propfind_complexity(child_probe + 1, property_count, limits).is_err(),
            "the root plus a full child probe must be rejected"
        );
        assert!(child_probe <= limits.max_rendered_properties);
    }
}

/// 覆盖请求属性数、目录项数和两个响应预算的确定性放大性质：结果要么在发布前被拒，
/// 要么完整 XML 外壳适合字节上限；任何生成用例都不得超过“条目 × 属性”上限。
/// Deterministic amplification property across request property count, directory item count, and
/// both response budgets. A result is rejected before publication or its complete XML envelope
/// fits the byte cap; no generated case may exceed the item × property cap.
#[test]
fn propfind_response_amplification_obeys_all_budget_functions() {
    const ITEM_COUNTS: [usize; 6] = [1, 2, 4, 8, 16, 33];
    const PROPERTY_COUNTS: [usize; 5] = [1, 2, 4, 8, 16];
    const RENDERED_LIMITS: [usize; 3] = [16, 64, 256];
    const RESPONSE_LIMITS: [usize; 3] = [1024, 4096, 16 * 1024];

    for property_count in PROPERTY_COUNTS {
        let properties = (0..property_count)
            .map(|index| format!("<X:p{index}/>"))
            .collect::<String>();
        let request_body = format!(
            "<D:propfind xmlns:D=\"DAV:\" xmlns:X=\"urn:ram:property\"><D:prop>{properties}</D:prop></D:propfind>"
        );
        assert!(request_body.len() <= DAV_BODY_LIMIT);

        for rendered_limit in RENDERED_LIMITS {
            for response_limit in RESPONSE_LIMITS {
                let limits = DavLimits {
                    max_properties: property_count,
                    max_rendered_properties: rendered_limit,
                    max_response_size: response_limit,
                };
                let request = parse_propfind_body(request_body.as_bytes(), limits)
                    .expect("generated request is within its input/property budgets");
                assert_eq!(propfind_property_count(&request), property_count);
                assert_eq!(
                    propfind_child_probe_limit(limits, property_count),
                    rendered_limit / property_count
                );

                for item_count in ITEM_COUNTS {
                    let items = (0..item_count)
                        .map(|index| PathItem {
                            path_type: PathType::File,
                            name: format!("item-{index}-<&?#"),
                            mtime: index as u64,
                            size: index as u64,
                            size_known: true,
                        })
                        .collect::<Vec<_>>();
                    let result = render_propfind_response(&items, "/", &request, limits);
                    if let Ok(content) = result {
                        let full_size = DAV_MULTISTATUS_PREFIX
                            .len()
                            .checked_add(content.len())
                            .and_then(|size| size.checked_add(DAV_MULTISTATUS_SUFFIX.len()))
                            .expect("bounded response size arithmetic");
                        assert!(full_size <= response_limit);
                        assert!(
                            item_count
                                .checked_mul(property_count)
                                .is_some_and(|count| count <= rendered_limit)
                        );
                    }
                }
            }
        }
    }
}

#[tokio::test]
async fn response_writer_enforces_full_multistatus_byte_limit() {
    let limits = DavLimits::hard_maximum();
    let mut below = DavXmlWriter::new(limits);
    below
        .push(&"x".repeat(limits.response_content_limit() - 1))
        .unwrap();
    assert_eq!(below.finish().len(), limits.response_content_limit() - 1);

    let content = "x".repeat(limits.response_content_limit());
    let mut exact = DavXmlWriter::new(limits);
    exact.push(&content).unwrap();
    let content = exact.finish();
    let mut response = Response::default();
    set_multistatus_response(&mut response, content);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.len(), limits.max_response_size);

    let mut over = DavXmlWriter::new(limits);
    over.push(&"x".repeat(limits.response_content_limit()))
        .unwrap();
    assert_response_budget(
        over.push("x").unwrap_err(),
        DavBudgetExceeded::new(
            AdmissionResource::WebDavResponseBytes,
            limits.max_response_size as u64,
            Some((limits.max_response_size + 1) as u64),
        ),
    );
}

#[tokio::test]
async fn request_budget_failure_uses_static_non_diagnostic_body() {
    let mut response = Response::default();
    reject_dav_request(
        &mut response,
        DavRequestError::BudgetExceeded(DavBudgetExceeded::new(
            AdmissionResource::WebDavPropertyNameBytes,
            16_384,
            Some(17_007),
        )),
    );
    assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"WebDAV property budget exceeded");
}

#[tokio::test]
async fn response_budget_failure_maps_to_insufficient_storage() {
    let mut response = Response::default();
    reject_dav_response(
        &mut response,
        DavResponseError::BudgetExceeded(DavBudgetExceeded::new(
            AdmissionResource::WebDavResponseBytes,
            1024,
            Some(1025),
        )),
    );
    assert_eq!(response.status(), StatusCode::INSUFFICIENT_STORAGE);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(body.as_ref(), b"WebDAV response budget exceeded");
}
