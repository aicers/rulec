//! Each modifier, its case rules, and the condition syntax, on hand-written
//! rules and synthetic events.

mod common;

use common::{TestEvent, compile_texts, matched_ids, rule_text, selection_matches};

fn uri(values: &[&str]) -> TestEvent {
    TestEvent::http().text("uri", values)
}

#[test]
fn plain_value_is_exact_and_caseless() {
    let sel = "        uri: '/Index.html'\n";
    assert!(selection_matches(sel, &uri(&["/index.HTML"])));
    assert!(!selection_matches(sel, &uri(&["/index.htm"])));
    assert!(!selection_matches(sel, &uri(&["/index.html?x"])));
}

#[test]
fn contains_startswith_endswith() {
    assert!(selection_matches(
        "        uri|contains: 'ABC'\n",
        &uri(&["xxabcxx"])
    ));
    assert!(!selection_matches(
        "        uri|contains: 'ABC'\n",
        &uri(&["xxabxcx"])
    ));
    assert!(selection_matches(
        "        uri|startswith: '/adm'\n",
        &uri(&["/admin"])
    ));
    assert!(!selection_matches(
        "        uri|startswith: '/adm'\n",
        &uri(&["x/admin"])
    ));
    assert!(selection_matches(
        "        uri|endswith: '.php'\n",
        &uri(&["/a.PHP"])
    ));
    assert!(!selection_matches(
        "        uri|endswith: '.php'\n",
        &uri(&["/a.php5"])
    ));
}

#[test]
fn wildcards_and_escapes() {
    let sel = "        uri: '/a*b?c'\n";
    assert!(selection_matches(sel, &uri(&["/aXXbYc"])));
    assert!(selection_matches(sel, &uri(&["/ab-c"])));
    assert!(
        selection_matches(sel, &uri(&["/abéc"])),
        "`?` matches one character"
    );
    assert!(!selection_matches(sel, &uri(&["/abc"])));
    let escaped = r"        uri: '/a\*b\?'
";
    assert!(selection_matches(escaped, &uri(&["/a*b?"])));
    assert!(!selection_matches(escaped, &uri(&["/aXbY"])));
}

#[test]
fn cased_makes_strings_case_sensitive() {
    let sel = "        uri|contains|cased: 'ABC'\n";
    assert!(selection_matches(sel, &uri(&["xABCx"])));
    assert!(!selection_matches(sel, &uri(&["xabcx"])));
    assert!(!selection_matches(
        "        uri|cased: 'Abc'\n",
        &uri(&["abc"])
    ));
    assert!(selection_matches(
        "        uri|cased: 'Abc'\n",
        &uri(&["Abc"])
    ));
}

#[test]
fn re_is_case_sensitive_unless_i() {
    assert!(!selection_matches(
        "        uri|re: 'ABC'\n",
        &uri(&["abc"])
    ));
    assert!(selection_matches(
        "        uri|re: 'ABC'\n",
        &uri(&["xABCx"])
    ));
    assert!(selection_matches(
        "        uri|re|i: 'ABC'\n",
        &uri(&["abc"])
    ));
    assert!(selection_matches(
        "        uri|re: 'ab+c$'\n",
        &uri(&["xabbbc"])
    ));
    assert!(!selection_matches(
        "        uri|re: 'ab+c$'\n",
        &uri(&["xabbbcd"])
    ));
}

#[test]
fn re_m_and_s() {
    let text = &["a\nb\nc"];
    assert!(!selection_matches("        uri|re: '^b$'\n", &uri(text)));
    assert!(selection_matches("        uri|re|m: '^b$'\n", &uri(text)));
    assert!(!selection_matches("        uri|re: 'a.b'\n", &uri(text)));
    assert!(selection_matches("        uri|re|s: 'a.b'\n", &uri(text)));
}

#[test]
fn ignoring_case_is_ascii_only() {
    assert!(selection_matches("        uri: 'É'\n", &uri(&["É"])));
    assert!(!selection_matches("        uri: 'É'\n", &uri(&["é"])));
    assert!(!selection_matches(
        "        uri|contains: 'straße'\n",
        &uri(&["STRASSE"])
    ));
    assert!(selection_matches(
        "        uri|contains: 'Café'\n",
        &uri(&["CAFé"])
    ));
}

#[test]
fn all_needs_every_value() {
    let sel = "        uri|contains|all:\n            - 'a'\n            - 'b'\n";
    assert!(selection_matches(sel, &uri(&["xaxbx"])));
    assert!(
        selection_matches(sel, &uri(&["xa", "bx"])),
        "each value in some field value"
    );
    assert!(!selection_matches(sel, &uri(&["xax"])));
    let any = "        uri|contains:\n            - 'a'\n            - 'b'\n";
    assert!(selection_matches(any, &uri(&["xax"])));
}

#[test]
fn exists() {
    let yes = "        ua|exists: true\n";
    let no = "        ua|exists: false\n";
    let with = TestEvent::http().text("ua", &[""]);
    let without = TestEvent::http().text("uri", &["/"]);
    assert!(selection_matches(yes, &with));
    assert!(!selection_matches(yes, &without));
    assert!(selection_matches(no, &without));
    assert!(!selection_matches(no, &with));
}

#[test]
fn neq() {
    let sel = "        method|neq: 'GET'\n";
    assert!(selection_matches(
        sel,
        &TestEvent::http().text("method", &["POST"])
    ));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().text("method", &["get"])
    ));
    assert!(!selection_matches(sel, &TestEvent::http()), "no value");
    let list = "        method|neq:\n            - 'GET'\n            - 'POST'\n";
    assert!(!selection_matches(
        list,
        &TestEvent::http().text("method", &["POST"])
    ));
    assert!(selection_matches(
        list,
        &TestEvent::http().text("method", &["PUT"])
    ));
    let num = "        status|neq: 200\n";
    assert!(selection_matches(
        num,
        &TestEvent::http().int("status", 404)
    ));
    assert!(!selection_matches(
        num,
        &TestEvent::http().text("status", &["200"])
    ));
    // A value that does not read as a number or an address makes `neq`
    // false, as it does the comparison it negates.
    assert!(!selection_matches(
        num,
        &TestEvent::http().text("status", &["abc"])
    ));
    assert!(selection_matches(
        num,
        &TestEvent::http().text("status", &["abc", "404"])
    ));
    // Listed beside a string, an integer still needs a number.
    let mixed = "        status|neq:\n            - 200\n            - 'abc'\n";
    assert!(selection_matches(
        mixed,
        &TestEvent::http().text("status", &["404"])
    ));
    assert!(!selection_matches(
        mixed,
        &TestEvent::http().text("status", &["xyz"])
    ));
    let net = "        resp_addr|cidr|neq: 10.0.0.0/8\n";
    assert!(selection_matches(
        net,
        &TestEvent::http().addr("resp_addr", "192.0.2.1")
    ));
    assert!(!selection_matches(
        net,
        &TestEvent::http().addr("resp_addr", "10.1.2.3")
    ));
    assert!(!selection_matches(
        net,
        &TestEvent::http().text("resp_addr", &["host"])
    ));
    assert!(selection_matches(
        net,
        &TestEvent::http().text("resp_addr", &["host", "192.0.2.1"])
    ));
}

#[test]
fn windash() {
    let sel = "        cmd|windash|contains: ' -enc '\n";
    for variant in [
        " -enc ",
        " /enc ",
        " \u{2013}enc ",
        " \u{2014}enc ",
        " \u{2015}enc ",
    ] {
        let event = TestEvent::http().text("cmd", &[&format!("powershell{variant}x")]);
        assert!(selection_matches(sel, &event), "{variant:?}");
    }
    assert!(!selection_matches(
        sel,
        &TestEvent::http().text("cmd", &["powershell +enc x"])
    ));
}

#[test]
fn base64_and_base64offset() {
    let exact = "        body|base64: 'abc'\n";
    assert!(selection_matches(
        exact,
        &TestEvent::http().text("body", &["YWJj"])
    ));
    assert!(!selection_matches(
        exact,
        &TestEvent::http().text("body", &["abc"])
    ));
    let contains = "        body|base64|contains: 'abc'\n";
    assert!(selection_matches(
        contains,
        &TestEvent::http().text("body", &["x YWJj x"])
    ));

    let offset = "        body|base64offset|contains: '/bin/bash'\n";
    // "echo /bin/bash -i" and "ab /bin/bash" put the value at two offsets.
    for encoded in [
        "ZWNobyAvYmluL2Jhc2ggLWk=",
        "YWIgL2Jpbi9iYXNo",
        "L2Jpbi9iYXNo",
    ] {
        assert!(
            selection_matches(offset, &TestEvent::http().text("body", &[encoded])),
            "{encoded}"
        );
    }
    assert!(!selection_matches(
        offset,
        &TestEvent::http().text("body", &["/bin/bash"])
    ));
}

#[test]
fn utf16_family() {
    let le = b"x\x00c\x00m\x00d\x00y\x00";
    let be = b"\x00x\x00c\x00m\x00d";
    assert!(selection_matches(
        "        f|utf16le|contains: 'cmd'\n",
        &TestEvent::http().bytes("f", le)
    ));
    assert!(selection_matches(
        "        f|wide|contains: 'cmd'\n",
        &TestEvent::http().bytes("f", le)
    ));
    assert!(!selection_matches(
        "        f|utf16le|contains: 'cmd'\n",
        &TestEvent::http().bytes("f", be)
    ));
    assert!(selection_matches(
        "        f|utf16be|contains: 'cmd'\n",
        &TestEvent::http().bytes("f", be)
    ));
    let bom = b"\xff\xfec\x00m\x00d\x00";
    assert!(selection_matches(
        "        f|utf16: 'cmd'\n",
        &TestEvent::http().bytes("f", bom)
    ));
    assert!(!selection_matches(
        "        f|utf16: 'cmd'\n",
        &TestEvent::http().bytes("f", &bom[2..])
    ));
    let wide_b64 = "        f|wide|base64offset|contains: 'cmd'\n";
    // Base64 of UTF-16LE "cmd": "YwBtAGQA".
    assert!(selection_matches(
        wide_b64,
        &TestEvent::http().text("f", &["..YwBtAGQA.."])
    ));
}

#[test]
fn modifiers_apply_in_the_order_written() {
    // `utf16` puts its BOM before the value it encodes: before the `*` that
    // `contains` added when `contains` comes first, after it otherwise.
    let bom_then_any = "        f|contains|utf16: 'cmd'\n";
    let any_then_bom = "        f|utf16|contains: 'cmd'\n";
    let bom_first = b"\xff\xfex\x00c\x00m\x00d\x00";
    let bom_inside = b"x\x00\xff\xfec\x00m\x00d\x00";
    assert!(selection_matches(
        bom_then_any,
        &TestEvent::http().bytes("f", bom_first)
    ));
    assert!(!selection_matches(
        bom_then_any,
        &TestEvent::http().bytes("f", bom_inside)
    ));
    assert!(selection_matches(
        any_then_bom,
        &TestEvent::http().bytes("f", bom_inside)
    ));
    assert!(!selection_matches(
        any_then_bom,
        &TestEvent::http().bytes("f", bom_first)
    ));
    // `startswith` before `wide` keeps its `*` through the encoding.
    assert!(selection_matches(
        "        f|startswith|wide: 'cmd'\n",
        &TestEvent::http().bytes("f", b"c\x00m\x00d\x00 \x00")
    ));
}

#[test]
fn numeric_comparisons() {
    let status = |v: &str| TestEvent::http().text("status", &[v]);
    assert!(selection_matches(
        "        status|gt: 400\n",
        &status("404")
    ));
    assert!(!selection_matches(
        "        status|gt: 400\n",
        &status("400")
    ));
    assert!(selection_matches(
        "        status|gte: 400\n",
        &status("400")
    ));
    assert!(selection_matches(
        "        status|lt: 400\n",
        &status("200")
    ));
    assert!(!selection_matches(
        "        status|lt: 400\n",
        &status("400")
    ));
    assert!(selection_matches(
        "        status|lte: 400\n",
        &status("400")
    ));
    assert!(selection_matches("        status|gt: -1\n", &status("-0")));
    assert!(selection_matches(
        "        status|gt: 400\n",
        &TestEvent::http().int("status", 500)
    ));
    assert!(!selection_matches(
        "        status|gt: 400\n",
        &status("500x")
    ));
    assert!(!selection_matches(
        "        status|lt: 400\n",
        &status("abc")
    ));
    assert!(selection_matches("        status: 200\n", &status("200")));
    assert!(!selection_matches("        status: 200\n", &status("abc")));
    assert!(selection_matches(
        "        resp_port: 443\n",
        &TestEvent::http().int("resp_port", 443)
    ));
}

#[test]
fn cidr() {
    let sel = "        resp_addr|cidr: 10.0.0.0/8\n";
    assert!(selection_matches(
        sel,
        &TestEvent::http().addr("resp_addr", "10.1.2.3")
    ));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().addr("resp_addr", "11.0.0.1")
    ));
    assert!(selection_matches(
        sel,
        &TestEvent::http().text("resp_addr", &["10.9.9.9"])
    ));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().text("resp_addr", &["not-an-ip"])
    ));
    let v6 = "        resp_addr|cidr: '2001:db8::/32'\n";
    assert!(selection_matches(
        v6,
        &TestEvent::http().addr("resp_addr", "2001:db8::1")
    ));
}

#[test]
fn fieldref() {
    let sel = "        host|fieldref: referer_host\n";
    let event = |host: &str, referer: &str| {
        TestEvent::http()
            .text("host", &[host])
            .text("referer_host", &[referer])
    };
    assert!(selection_matches(sel, &event("Example.com", "example.COM")));
    assert!(!selection_matches(sel, &event("a.com", "b.com")));
    assert!(!selection_matches(
        sel,
        &TestEvent::http().text("host", &["a"])
    ));
    let cased = "        host|fieldref|cased: referer_host\n";
    assert!(!selection_matches(
        cased,
        &event("Example.com", "example.com")
    ));
    let neq = "        host|fieldref|neq: referer_host\n";
    assert!(selection_matches(neq, &event("a.com", "b.com")));
    assert!(!selection_matches(neq, &event("a.com", "A.com")));
    assert!(!selection_matches(
        neq,
        &TestEvent::http().text("host", &["a"])
    ));
}

#[test]
fn len() {
    let event = |v: &str| uri(&[v]);
    assert!(selection_matches("        uri|len: 5\n", &event("abcde")));
    assert!(!selection_matches("        uri|len: 5\n", &event("abcd")));
    assert!(selection_matches("        uri|len|gt: 3\n", &event("abcd")));
    assert!(!selection_matches("        uri|len|gt: 3\n", &event("abc")));
    assert!(selection_matches("        uri|len|gte: 3\n", &event("abc")));
    assert!(selection_matches("        uri|len|lt: 3\n", &event("")));
    assert!(selection_matches("        uri|len|lte: 3\n", &event("abc")));
    assert!(selection_matches("        uri|len|neq: 3\n", &event("ab")));
    assert!(!selection_matches(
        "        uri|len: 0\n",
        &TestEvent::http()
    ));
    assert!(selection_matches(
        "        uri|len: 2\n",
        &TestEvent::http().bytes("uri", &[0xff, 0x00])
    ));
}

#[test]
fn conditions() {
    let detection = "    sel_a:\n        a: '1'\n    sel_b:\n        b: '1'\n    filter:\n        c: '1'\n    _x:\n        d: '1'\n";
    let rules: Vec<String> = [
        ("one_of", "1 of sel_*"),
        ("all_of", "all of sel_*"),
        ("them", "1 of them"),
        ("all_them", "all of them"),
        ("parens", "(sel_a or sel_b) and not filter"),
        ("not_prec", "not sel_a and sel_b"),
        ("list", "[sel_a, filter]"),
    ]
    .iter()
    .map(|(id, cond)| {
        let cond = if cond.starts_with('[') {
            "    condition:\n        - sel_a and sel_b\n        - filter\n".to_string()
        } else {
            format!("    condition: {cond}\n")
        };
        rule_text(id, &format!("{detection}{cond}"))
    })
    .collect();
    let compiled = compile_texts(&rules);
    let ev = |pairs: &[(&str, &str)]| {
        pairs
            .iter()
            .fold(TestEvent::http(), |e, (k, v)| e.text(k, &[v]))
    };
    let ids = |e: &TestEvent| matched_ids(&compiled, e, &[]);

    assert_eq!(ids(&ev(&[("a", "1")])), vec!["one_of", "them", "parens"]);
    assert_eq!(
        ids(&ev(&[("a", "1"), ("b", "1")])),
        vec!["one_of", "all_of", "them", "parens", "list"]
    );
    assert_eq!(
        ids(&ev(&[("a", "1"), ("b", "1"), ("c", "1")])),
        vec!["one_of", "all_of", "them", "all_them", "list"]
    );
    assert_eq!(
        ids(&ev(&[("a", "1"), ("b", "1"), ("c", "1"), ("d", "1")])),
        vec!["one_of", "all_of", "them", "all_them", "list"]
    );
    assert_eq!(
        ids(&ev(&[("b", "1")])),
        vec!["one_of", "them", "parens", "not_prec"]
    );
    assert_eq!(ids(&ev(&[("c", "1")])), vec!["them", "list"]);
    assert_eq!(ids(&ev(&[("d", "1")])), Vec::<String>::new());
}

#[test]
fn list_of_maps_is_or() {
    let detection = "    selection:\n        - uri: '/a'\n        - host: 'b'\n          ua: 'c'\n    condition: selection\n";
    let compiled = compile_texts(&[rule_text("r", detection)]);
    let ids = |e: &TestEvent| matched_ids(&compiled, e, &[]);
    assert_eq!(ids(&uri(&["/a"])), vec!["r"]);
    assert!(ids(&TestEvent::http().text("host", &["b"])).is_empty());
    assert_eq!(
        ids(&TestEvent::http().text("host", &["b"]).text("ua", &["c"])),
        vec!["r"]
    );
}
