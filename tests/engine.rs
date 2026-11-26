//! Compiling and matching: always-checked rules, rules vectorscan rejects,
//! `%home_net%`, OS selection, matched fields, value semantics and threads.

mod common;

use common::{
    TestEvent, compile_texts, matched_ids, rule_text, rule_text_with, selection_matches,
    selection_rule,
};
use giganto_client::{RawEventKind, ingest::endpoint::OsFamily};
use rulec::{Cidr, CompiledRules, KindCount, Source, compile};

fn sel(selection: &str) -> String {
    format!("    selection:\n{selection}    condition: selection\n")
}

#[test]
fn always_checked_rules() {
    let rules = vec![
        // Address and port only.
        rule_text(
            "addr_port",
            &sel("        resp_addr|cidr: 10.0.0.0/8\n        resp_port: 8080\n"),
        ),
        // Numbers only.
        rule_text("numeric", &sel("        status|gte: 500\n")),
        // True through `not` alone.
        rule_text(
            "not_only",
            "    selection:\n        uri|contains: '/admin'\n    condition: not selection\n",
        ),
        // A branch without patterns under `or`.
        rule_text(
            "or_branch",
            "    pattern:\n        uri|contains: 'evil'\n    port:\n        resp_port: 22\n    condition: pattern or port\n",
        ),
        // Literals under AND: never always checked.
        rule_text(
            "literal_and",
            &sel("        uri|contains: '/x'\n        host: 'example.com'\n"),
        ),
        // A literal ANDed with a residual condition: not always checked.
        rule_text(
            "literal_and_port",
            &sel("        uri|contains: '/y'\n        resp_port: 80\n"),
        ),
    ];
    let compiled = compile_texts(&rules);
    assert_eq!(
        compiled.stats().always_check(),
        vec![KindCount {
            kind: RawEventKind::Http,
            count: 4
        }]
    );

    // None of these events matches a pattern.
    let ids = |e: &TestEvent| matched_ids(&compiled, e, &[]);
    assert_eq!(
        ids(&TestEvent::http()
            .addr("resp_addr", "10.1.1.1")
            .int("resp_port", 8080)
            .text("uri", &["/admin"])),
        vec!["addr_port"]
    );
    assert_eq!(
        ids(&TestEvent::http()
            .text("status", &["503"])
            .text("uri", &["/admin"])),
        vec!["numeric"]
    );
    assert_eq!(
        ids(&TestEvent::http().text("uri", &["/home"])),
        vec!["not_only"]
    );
    assert_eq!(
        ids(&TestEvent::http()
            .int("resp_port", 22)
            .text("uri", &["/admin"])),
        vec!["or_branch"]
    );
    // And a pattern still decides the literal rules.
    assert_eq!(
        ids(&TestEvent::http()
            .text("uri", &["/admin/x"])
            .text("host", &["EXAMPLE.com"])),
        vec!["literal_and"]
    );
}

#[test]
fn a_rule_vectorscan_rejects_is_left_out_alone() {
    let rules = vec![
        rule_text("ok_1", &sel("        uri|contains: 'a'\n")),
        rule_text("backref", &sel("        uri|re: '(a)\\1'\n")),
        rule_text("ok_2", &sel("        uri|re: 'b+'\n")),
        rule_text("empty_re", &sel("        uri|re: 'x*'\n")),
    ];
    let compiled = compile_texts(&rules);
    let stats = compiled.stats();
    assert_eq!(stats.accepted(), 2);
    let excluded: Vec<_> = stats
        .excluded()
        .iter()
        .map(|e| (e.source, e.source_rule_id.as_str()))
        .collect();
    assert_eq!(
        excluded,
        vec![(Source::SigmaHq, "backref"), (Source::SigmaHq, "empty_re")]
    );
    for e in stats.excluded() {
        assert!(!e.message.is_empty());
    }
    assert!(stats.db_size() > 0);
    assert_eq!(
        matched_ids(&compiled, &TestEvent::http().text("uri", &["aabb"]), &[]),
        vec!["ok_1", "ok_2"]
    );
}

#[test]
fn compile_stats() {
    let mut rules = vec![
        rule_text("p1", &sel("        uri|contains: 'a'\n")),
        rule_text("p2", &sel("        uri|contains: 'a'\n")),
        rule_text("bad", &sel("        uri|re: '(?<=a)b'\n")),
        rule_text_with("t1", "tls", "", &sel("        resp_port: 443\n")),
        rule_text_with(
            "t2",
            "tls",
            "",
            &sel("        server_name|endswith: '.example'\n"),
        ),
    ];
    rules.push(rules[0].clone());
    let compiled = compile_texts(&rules);
    let stats = compiled.stats();
    assert_eq!(
        stats.accepted(),
        5,
        "duplicates are kept: {:?}",
        stats.excluded()
    );
    assert_eq!(stats.excluded().len(), 1);
    assert_eq!(stats.excluded()[0].source_rule_id, "bad");
    assert_eq!(
        stats.always_check(),
        vec![KindCount {
            kind: RawEventKind::Tls,
            count: 1
        }]
    );
    assert!(stats.db_size() > 0);
    assert_eq!(compiled.rules().count(), 5);
    // Both copies of the same id match.
    assert_eq!(
        matched_ids(&compiled, &TestEvent::http().text("uri", &["a"]), &[]),
        vec!["p1", "p2", "p1"]
    );
}

#[test]
fn home_net_follows_the_list_without_recompiling() {
    let compiled = compile_texts(&[
        rule_text(
            "home",
            &sel("        resp_addr|expand|cidr: '%home_net%'\n"),
        ),
        rule_text(
            "home_or_doc",
            &sel(
                "        resp_addr|expand|cidr:\n            - '%home_net%'\n            - 192.0.2.0/24\n",
            ),
        ),
    ]);
    let event = TestEvent::http().addr("resp_addr", "10.1.2.3");
    let doc = TestEvent::http().addr("resp_addr", "192.0.2.7");
    let ten: Vec<Cidr> = vec!["10.0.0.0/8".parse().unwrap()];
    let other: Vec<Cidr> = vec![
        "172.16.0.0/12".parse().unwrap(),
        "192.168.0.0/16".parse().unwrap(),
    ];
    assert_eq!(
        matched_ids(&compiled, &event, &ten),
        vec!["home", "home_or_doc"]
    );
    assert!(matched_ids(&compiled, &event, &other).is_empty());
    assert!(matched_ids(&compiled, &event, &[]).is_empty());
    assert_eq!(matched_ids(&compiled, &doc, &[]), vec!["home_or_doc"]);
    let text = TestEvent::http().text("resp_addr", &["10.0.0.1"]);
    assert_eq!(
        matched_ids(&compiled, &text, &ten),
        vec!["home", "home_or_doc"]
    );
}

#[test]
fn os_rules_need_a_matching_host_header() {
    let compiled = compile_texts(&[
        rule_text_with(
            "win",
            "process_create",
            "os: windows\n",
            &sel("        image|endswith: 'cmd.exe'\n"),
        ),
        rule_text_with(
            "any",
            "process_create",
            "",
            &sel("        image|endswith: 'cmd.exe'\n"),
        ),
    ]);
    let kind = RawEventKind::ProcessCreate;
    let event = |os: Option<OsFamily>| {
        let e = TestEvent::new(kind).text("image", &["C:\\cmd.exe"]);
        match os {
            Some(os) => e.os(os),
            None => e,
        }
    };
    assert_eq!(compiled.skipped_os_events(kind), 0);
    assert_eq!(
        matched_ids(&compiled, &event(Some(OsFamily::Windows)), &[]),
        vec!["win", "any"]
    );
    assert_eq!(
        matched_ids(&compiled, &event(Some(OsFamily::Linux)), &[]),
        vec!["any"]
    );
    assert_eq!(compiled.skipped_os_events(kind), 0);
    assert_eq!(matched_ids(&compiled, &event(None), &[]), vec!["any"]);
    assert_eq!(compiled.skipped_os_events(kind), 1);
    assert_eq!(
        matched_ids(
            &compiled,
            &event(Some(OsFamily::Other("haiku".to_string()))),
            &[]
        ),
        vec!["any"]
    );
    assert_eq!(compiled.skipped_os_events(kind), 1);
    assert_eq!(matched_ids(&compiled, &event(None), &[]), vec!["any"]);
    assert_eq!(compiled.skipped_os_events(kind), 2);
    assert_eq!(compiled.skipped_os_events(RawEventKind::Http), 0);
}

#[test]
fn a_match_names_the_fields_that_made_it() {
    let compiled = compile_texts(&[rule_text(
        "r",
        "    selection:\n        uri|contains: '/a'\n        host: 'b'\n    alt:\n        ua: 'never'\n    filter:\n        ref: 'bad'\n    condition: (selection or alt) and not filter\n",
    )]);
    let event = TestEvent::http()
        .text("uri", &["/a"])
        .text("host", &["B"])
        .text("ua", &["curl"])
        .text("ref", &["good"]);
    let mut matcher = compiled.matcher();
    let matches = matcher.matches(&event, &[]).unwrap();
    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].rule().source_rule_id(), "r");
    assert_eq!(matches[0].rule().title(), "rule r");
    assert_eq!(matches[0].fields(), ["host", "uri"]);
}

#[test]
fn several_values_and_missing_values() {
    let ua = |values: &[&str]| TestEvent::http().text("ua", values);
    assert!(selection_matches(
        "        ua: 'curl'\n",
        &ua(&["wget", "curl"])
    ));
    assert!(selection_matches(
        "        ua|re: '^c'\n",
        &ua(&["wget", "curl"])
    ));
    assert!(selection_matches(
        "        ua|len: 4\n",
        &ua(&["x", "curl"])
    ));
    assert!(selection_matches(
        "        ua|neq: 'curl'\n",
        &ua(&["curl", "wget"])
    ));

    let none = TestEvent::http().text("uri", &["/"]);
    assert!(selection_matches("        ua: null\n", &none));
    assert!(selection_matches("        ua|exists: false\n", &none));
    assert!(!selection_matches("        ua|neq: 'curl'\n", &none));
    assert!(!selection_matches("        ua|contains: ''\n", &none));
    assert!(!selection_matches("        ua: '*'\n", &none));
    assert!(!selection_matches("        ua|fieldref: uri\n", &none));
    assert!(!selection_matches("        uri|fieldref: ua\n", &none));

    let empty = ua(&[""]);
    assert!(selection_matches("        ua: ''\n", &empty));
    assert!(!selection_matches("        ua: null\n", &empty));
    assert!(selection_matches("        ua|exists: true\n", &empty));
    assert!(!selection_matches("        ua: ''\n", &ua(&["x"])));
}

#[test]
fn values_that_do_not_read() {
    let v = |s: &str| TestEvent::http().text("f", &[s]);
    for bad in ["", "abc", "1.5", "0x10", " 1", "99999999999999999999"] {
        assert!(
            !selection_matches("        f|gt: -100\n", &v(bad)),
            "{bad:?}"
        );
        assert!(
            !selection_matches("        f|lt: 100\n", &v(bad)),
            "{bad:?}"
        );
    }
    for bad in ["", "10.0.0", "10.0.0.1/8", " 10.0.0.1", "host"] {
        assert!(
            !selection_matches("        f|cidr: 0.0.0.0/0\n", &v(bad)),
            "{bad:?}"
        );
    }
    assert!(!selection_matches(
        "        f|cidr: 0.0.0.0/0\n",
        &TestEvent::http().int("f", 1)
    ));
}

#[test]
fn conditions_that_match_an_empty_value() {
    let compiled = compile(vec![
        selection_rule("empty", "        ua: ''\n"),
        selection_rule("star", "        ua: '*'\n"),
        selection_rule("stars", "        ua: '**'\n"),
        selection_rule("contains_empty", "        ua|contains: ''\n"),
        selection_rule("startswith_empty", "        ua|startswith: ''\n"),
        selection_rule("endswith_empty", "        ua|endswith: ''\n"),
    ])
    .unwrap();
    assert!(compiled.stats().excluded().is_empty());
    assert_eq!(compiled.stats().accepted(), 6);
    let ids = |e: &TestEvent| matched_ids(&compiled, e, &[]);
    let all_but_empty = vec![
        "star",
        "stars",
        "contains_empty",
        "startswith_empty",
        "endswith_empty",
    ];
    assert_eq!(ids(&TestEvent::http().text("ua", &["x"])), all_but_empty);
    let mut everything = vec!["empty"];
    everything.extend(&all_but_empty);
    assert_eq!(ids(&TestEvent::http().text("ua", &[""])), everything);
    assert!(ids(&TestEvent::http()).is_empty());
}

#[test]
fn other_kinds_do_not_match() {
    let compiled = compile_texts(&[rule_text("r", &sel("        uri|contains: 'a'\n"))]);
    assert!(
        matched_ids(
            &compiled,
            &TestEvent::new(RawEventKind::Tls).text("uri", &["a"]),
            &[]
        )
        .is_empty()
    );
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn threads_share_compiled_rules() {
    assert_send_sync::<CompiledRules>();

    let texts: Vec<String> = (0..40)
        .map(|i| {
            rule_text(
                &format!("r{i}"),
                &sel(&format!(
                    "        uri|contains: '/p{}'\n        status|gte: {}\n",
                    i % 7,
                    (i % 5) * 100
                )),
            )
        })
        .chain([rule_text("port", &sel("        resp_port: 22\n"))])
        .collect();
    let compiled = compile_texts(&texts);
    let events: Vec<TestEvent> = (0..200)
        .map(|i| {
            TestEvent::http()
                .text("uri", &[&format!("/x/p{}/y", i % 9)])
                .text("status", &[&format!("{}", (i % 6) * 100)])
                .int("resp_port", i % 23)
        })
        .collect();

    let mut matcher = compiled.matcher();
    let expected: Vec<Vec<String>> = events
        .iter()
        .map(|e| {
            matcher
                .matches(e, &[])
                .unwrap()
                .iter()
                .map(|m| m.rule().source_rule_id().to_string())
                .collect()
        })
        .collect();
    assert!(expected.iter().any(|ids| !ids.is_empty()));

    std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4)
            .map(|_| {
                scope.spawn(|| {
                    let mut matcher = compiled.matcher();
                    events
                        .iter()
                        .map(|e| {
                            matcher
                                .matches(e, &[])
                                .unwrap()
                                .iter()
                                .map(|m| m.rule().source_rule_id().to_string())
                                .collect::<Vec<_>>()
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        for handle in handles {
            assert_eq!(handle.join().unwrap(), expected);
        }
    });
}
