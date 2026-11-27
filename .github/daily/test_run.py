"""All network and issue writes are replaced with fakes in this suite."""
import hashlib
import io
import json
from pathlib import Path
import tempfile
import tarfile
from types import SimpleNamespace

import make_probes
import urllib.error
import unittest
from unittest import mock
import zipfile

import run


class FakeGithub:
    def __init__(self, existing=()):
        self.existing = list(existing)
        self.writes = []

    def issues(self):
        return self.existing

    def create(self, title, body):
        self.writes.append((title, body))
        self.existing.append({"body": body, "state": "open"})
        return "https://github.com/example/test/issues/123"


def rule(sid, rev=1, mark=None, classes=("suricata_only",)):
    pairs = [{"key": {"pcap": "public", "flow": 42 + n}, "classification": c, "evidence": [{"tuple": ["10.0.0.1", 1234, "1.2.3.4", 80, 6], "kind": "Http", "fields": ["uri"]}]} for n, c in enumerate(c for c in classes if c != "equal")]
    return {"sid": str(sid), "rev": rev, "msg": "test message", "classification": list(classes), "input_limit": mark == "input", "threshold": mark == "threshold", "pairs": pairs}


def report(source, error=None):
    return {"source": source, "error": error, "input_count": 2, "accepted_ids": ["1"], "summary": {"source_version": {"version": "v1"}, "rulec_version": "0.1.0", "accepted": {"EtSignature": 1}, "dropped": {"needs_state": ["2"]}}}


class DailyTests(unittest.TestCase):
    def test_download_authentication_is_scoped_to_github_api(self):
        for url, authenticated in [
            ("https://api.github.com/repos/SigmaHQ/sigma/releases/latest", True),
            ("https://github.com/SigmaHQ/sigma/archive/test.zip", False),
            ("https://rules.emergingthreats.net/open/version.txt", False),
            ("https://api.github.com.example.test/data", False),
            ("http://api.github.com/example", False),
        ]:
            with self.subTest(url=url), mock.patch.object(run.urllib.request, "build_opener") as build:
                build.return_value.open.return_value = io.BytesIO(b"download")
                self.assertEqual(run.fetch(url, "test-token"), b"download")
                request = build.return_value.open.call_args.args[0]
                self.assertEqual(request.get_header("Authorization"), "Bearer test-token" if authenticated else None)

    def test_download_redirect_does_not_forward_token_to_storage(self):
        request = run.urllib.request.Request("https://api.github.com/example", headers={"Authorization": "Bearer test-token"})
        redirect = run.PublicDownloadRedirect()
        for target, authenticated in [("https://api.github.com/next", True), ("https://storage.example.test/signed", False), ("http://api.github.com/next", False)]:
            redirected = redirect.redirect_request(request, None, 302, "Found", {}, target)
            self.assertEqual(redirected.get_header("Authorization"), "Bearer test-token" if authenticated else None)

    def test_sources_fail_independently(self):
        calls = []
        def fetch(url):
            calls.append(url)
            if url.endswith("version.txt"):
                return b"1234"
            if url.endswith("tar.gz"):
                return b"tar bytes"
            if url.endswith("releases/latest"):
                raise OSError("simulated Sigma outage")
            if "commits?" in url:
                return json.dumps([{"sha": "a" * 40}]).encode()
            return b"zip bytes"
        with tempfile.TemporaryDirectory() as name:
            result = run.download_sources(Path(name), fetch)
            self.assertIsNone(result[0]["error"])
            self.assertIsNotNone(result[1]["error"])
            self.assertIsNone(result[2]["error"])
            self.assertEqual(result[2]["version"], "a" * 40)
            self.assertEqual(len(calls), 5)

    def test_download_failure_records_http_status_without_response_body(self):
        def fetch(url):
            raise urllib.error.HTTPError(url, 503, "Service Unavailable", None, None)
        with tempfile.TemporaryDirectory() as name:
            reports = run.download_sources(Path(name), fetch)
            self.assertEqual(len(reports), 3)
            self.assertTrue(all("HTTP 503" in report["error"] for report in reports))

    def test_et_download_failure_does_not_stop_sigma(self):
        def fetch(url):
            if "emergingthreats.net" in url:
                raise OSError("simulated ET outage")
            if url.endswith("releases/latest"):
                return json.dumps({"tag_name": "v-test", "assets": [{"name": "sigma_all_rules.zip", "browser_download_url": "https://example.test/release"}]}).encode()
            if "commits?" in url:
                return json.dumps([{"sha": "b" * 40}]).encode()
            return b"zip bytes"
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            result = run.download_sources(work, fetch)
            self.assertIsNotNone(result[0]["error"])
            self.assertTrue(all(r["error"] is None for r in result[1:]))
            run.save(work / "conversion.json", [report("et_open", "conversion failed"), report("sigma_hq"), report("sigma_hq_emerging")])
            def forbidden(*args, **kwargs):
                self.fail("ET failure must skip all Suricata and pcap I/O")
            run.run_suricata(work, work, get=forbidden, execute=forbidden)
            self.assertEqual(run.load(work / "pcap-runs.json"), [])
            run.save(work / "differential.json", {"status": "skipped", "reason": "ET conversion failed", "errors": []})
            self.assertTrue(run.finish(work))
            self.assertIn("ET conversion failed", (work / "summary.md").read_text())

    def test_sha_mismatch_never_writes_or_uses_pcap(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            entry = {"name": "bad", "url": "https://example.test/bad.pcap", "sha256": "0" * 64}
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                run.checked_pcap(entry, work, lambda _: b"wrong")
            self.assertFalse((work / "bad.pcap").exists())
            entry["sha256"] = hashlib.sha256(b"right").hexdigest()
            self.assertEqual(run.checked_pcap(entry, work, lambda _: b"right").read_bytes(), b"right")

    def test_pcap_failures_exclude_only_bad_inputs_and_continue(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            run.save(work / "conversion.json", [report("et_open")])
            with tarfile.open(work / "et.tar.gz", "w:gz"):
                pass
            entries = [{"name": label, "url": "https://example.test/" + label, "sha256": hashlib.sha256(b"pcap").hexdigest()} for label in ["bad", "missing", "good"]]
            entries[0]["sha256"] = "0" * 64
            run.save(work / "manifest.json", entries)
            executions = []
            def fetch(url):
                if url.endswith("missing"):
                    raise OSError("offline")
                return b"pcap"
            def execute(command, **kwargs):
                if command == ["suricata", "-V"]:
                    return SimpleNamespace(stdout="This is Suricata version 7.0.3 RELEASE", returncode=0)
                if "--dump-config" in command:
                    return SimpleNamespace(stdout="vars.address-groups.HOME_NET = [" + ",".join(run.HOME_NET) + "]\n", returncode=0)
                executions.append(command)
                log = Path(command[command.index("-l") + 1])
                (log / "eve.json").write_text("")
                return SimpleNamespace(stdout="", returncode=0)
            run.run_suricata(work, work, work / "manifest.json", fetch, execute)
            results = run.load(work / "pcap-runs.json")
            self.assertIn("SHA-256", results[0]["error"])
            self.assertIsNotNone(results[1]["error"])
            self.assertIsNone(results[2]["error"])
            self.assertEqual(len(executions), 1)
            self.assertIn("--init-errors-fatal", executions[0])

    def test_public_manifest_is_pinned_with_provenance(self):
        for entry in run.load(run.HERE / "pcaps.json"):
            self.assertTrue(all(entry.get(k) for k in ["name", "url", "sha256", "source", "license", "coverage"]))
            self.assertRegex(entry["sha256"], r"^[a-f0-9]{64}$")
            if "bundled_path" in entry:
                fixture = (run.HERE / "pcaps" / Path(entry["bundled_path"]).name).read_bytes()
                self.assertEqual(make_probes.generate(), fixture)
                self.assertEqual(hashlib.sha256(fixture).hexdigest(), entry["sha256"])
            else:
                self.assertRegex(entry["url"], r"^https://raw.githubusercontent.com/OISF/suricata-verify/[a-f0-9]{40}/")

    def test_et_selection_matches_shared_path_cases(self):
        for case in run.load(run.HERE / "et-path-cases.json"):
            self.assertEqual(run.included_et(case["path"]), case["included"], case["path"])

    def test_effective_suricata_networks_are_verified(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            run.save(work / "conversion.json", [report("et_open")])
            (work / "et.tar.gz").write_bytes(b"not opened before config validation")
            for networks in ["[10.0.0.0/8]", "any", ""]:
                def execute(command, **kwargs):
                    if command == ["suricata", "-V"]:
                        return SimpleNamespace(stdout="This is Suricata version 7.0.3 RELEASE")
                    self.assertIn("--dump-config", command)
                    self.assertIn("vars.address-groups.HOME_NET=[" + ",".join(run.HOME_NET) + "]", command)
                    return SimpleNamespace(stdout="vars.address-groups.HOME_NET = " + networks)
                with self.assertRaisesRegex(ValueError, "effective HOME_NET"):
                    run.run_suricata(work, work, execute=execute)
                self.assertFalse((work / "suricata.json").exists())

    def test_wrong_suricata_version_is_rejected_before_any_replay(self):
        for version in ["7.0.30", "8.0.3", "unknown"]:
            with self.subTest(version=version), tempfile.TemporaryDirectory() as name:
                work = Path(name)
                run.save(work / "conversion.json", [report("et_open")])
                execute = mock.Mock(return_value=SimpleNamespace(stdout=f"This is Suricata version {version} RELEASE"))
                with self.assertRaisesRegex(ValueError, "exactly Suricata 7.0.3"):
                    run.run_suricata(work, work, execute=execute)
                execute.assert_called_once_with(["suricata", "-V"], capture_output=True, text=True, check=True)
                self.assertFalse((work / "suricata.rules").exists())

    def test_replay_failure_preserves_other_pcaps_without_signature_diagnostics(self):
        with tempfile.TemporaryDirectory() as name:
            work = Path(name)
            run.save(work / "conversion.json", [report("et_open")])
            with tarfile.open(work / "et.tar.gz", "w:gz"):
                pass
            entries = [{"name": label, "url": "https://example.test/" + label, "sha256": hashlib.sha256(b"pcap").hexdigest()} for label in ["bad", "good"]]
            run.save(work / "manifest.json", entries)
            executions = []
            def execute(command, **kwargs):
                if command == ["suricata", "-V"]:
                    return SimpleNamespace(stdout="This is Suricata version 7.0.3 RELEASE")
                if "--dump-config" in command:
                    return SimpleNamespace(stdout="vars.address-groups.HOME_NET = [" + ",".join(run.HOME_NET) + "]\n", returncode=0)
                executions.append(command)
                log = Path(command[command.index("-l") + 1])
                if log.name == "bad":
                    return SimpleNamespace(returncode=1, stdout="alert tcp secret signature", stderr="detection: converted signature")
                (log / "eve.json").write_text("")
                return SimpleNamespace(returncode=0)
            run.run_suricata(work, work, work / "manifest.json", lambda _: b"pcap", execute)
            results = run.load(work / "pcap-runs.json")
            self.assertEqual(results[0]["error"], "Suricata exited 1")
            self.assertIsNone(results[0]["eve"])
            self.assertIsNone(results[1]["error"])
            self.assertEqual(len(executions), 2)
            text = json.dumps(results)
            self.assertNotIn("alert tcp", text)
            self.assertNotIn("detection:", text)

    def test_first_run_and_deltas_including_new_ids(self):
        first = report("et_open")
        self.assertTrue(run.delta([first], None)["first_run"])
        second = json.loads(json.dumps(first))
        second["accepted_ids"] = ["2", "3"]
        second["summary"]["accepted"]["EtSignature"] = 2
        second["summary"]["dropped"] = {"needs_state": ["1"], "raw_payload": ["4"]}
        second["summary"]["source_version"]["version"] = "v2"
        change = run.delta([second], [first])["sources"][0]
        self.assertEqual(change["accepted_delta"], {"EtSignature": 1})
        self.assertEqual(change["dropped_delta"], {"needs_state": 0, "raw_payload": 1})
        self.assertEqual(change["newly_dropped_ids"], ["1", "4"])
        self.assertEqual(change["newly_accepted_ids"], ["2", "3"])
        self.assertEqual(change["source_version"]["after"]["version"], "v2")

    def test_issue_plan_open_closed_marks_revisions_and_cap(self):
        existing = [{"body": run.marker(rule(1)), "state": "open"}, {"body": run.marker(rule(2)), "state": "closed"}]
        rules = [rule(1), rule(2), rule(1, 2), rule(3, mark="input"), rule(4, mark="threshold")] + [rule(n) for n in range(10, 35)]
        planned, deferred = run.issue_plan(rules, existing)
        self.assertEqual(len(planned), 20)
        self.assertEqual(len(deferred), 6)
        self.assertEqual((planned[0]["sid"], planned[0]["rev"]), ("1", 2))
        self.assertNotIn("3", [r["sid"] for r in planned])

    def test_issue_plan_treats_rules_in_both_classes_as_before(self):
        both = ("suricata_only", "rulec_only")
        existing = [{"body": run.marker(rule(5, classes=both)), "state": "closed"}]
        rules = [
            rule(1, classes=both), rule(1, classes=both), rule(1, 2, classes=both),
            rule(2, classes=both, mark="input"), rule(3, classes=both, mark="threshold"),
            rule(4, classes=("equal",)), rule(5, classes=both),
            rule(6), rule(7, classes=("rulec_only",)), rule(8, classes=("rulec_only",), mark="threshold"),
        ]
        planned, deferred = run.issue_plan(rules, existing)
        self.assertEqual([(r["sid"], r["rev"]) for r in planned], [("1", 1), ("1", 2), ("6", 1), ("7", 1)])
        self.assertEqual(deferred, [])

    def test_issue_body_names_every_class_of_the_rule(self):
        context = {"run_url": "https://example.test/run", "source_version": "v1", "rulec_version": "0.1.0"}
        body = run.issue_body(rule(1, classes=("suricata_only", "rulec_only")), context)
        details = json.loads(body.split("```json\n", 1)[1].split("\n```", 1)[0])
        self.assertEqual(details["분류"], ["suricata_only", "rulec_only"])
        self.assertEqual([p["classification"] for p in details["어긋난 쌍"]], ["suricata_only", "rulec_only"])

    def test_summary_lists_every_class_of_compared_rules(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            run.save(output / "conversion.json", [report("et_open")])
            run.save(output / "differential.json", {
                "status": "completed", "errors": [],
                "counts": {"equal": 1, "suricata_only": 1, "rulec_only": 1},
                "coverage": {"http_response": [
                    {"sid": "1", "classification": ["suricata_only", "rulec_only"]},
                    {"sid": "2", "classification": ["equal"]},
                ]},
            })
            self.assertFalse(run.finish(output))
            summary = (output / "summary.md").read_text()
            self.assertIn("- http_response: 1 (suricata_only, rulec_only), 2 (equal)", summary)
            self.assertNotIn("both", summary)

    def test_only_default_branch_schedule_publishes_with_fake_api(self):
        context = {"run_url": "https://example.test/run", "source_version": "v1", "rulec_version": "0.1.0"}
        for event, branch, allowed in [("pull_request", "main", False), ("workflow_dispatch", "main", False), ("schedule", "feature", False), ("schedule", "main", True)]:
            with self.subTest(event=event, branch=branch), tempfile.TemporaryDirectory() as name:
                output = Path(name)
                run.save(output / "differential.json", {"rules": [rule(n) for n in range(25)]})
                api = FakeGithub()
                result = run.publish(output, api, event, branch, "main", context)
                self.assertEqual(len(api.writes), 20 if allowed else 0)
                self.assertEqual(len(result["deferred"]), 5)
                if allowed:
                    for title, body in api.writes:
                        self.assertIn("판정 차이", title)
                        self.assertIn("test message", body)
                        self.assertNotIn("alert tcp", body)
                        self.assertNotIn("detection:", body)
                    retry = run.publish(output, api, event, branch, "main", context)
                    self.assertEqual(len(retry["created"]), 0)
                    self.assertEqual(retry["already_created_this_run"], 20)
                    self.assertEqual(len(retry["deferred"]), 5)
                    next_run = {**context, "run_url": "https://example.test/next-run"}
                    self.assertEqual(len(run.publish(output, api, event, branch, "main", next_run)["created"]), 5)

    def test_github_reads_all_issue_states_filters_prs_and_verifies_create(self):
        class Api(run.Github):
            def __init__(self):
                self.calls = []
            def request(self, path, body=None):
                self.calls.append((path, body))
                if "&page=1" in path:
                    return [{"number": n, "body": "", **({"pull_request": {}} if n == 0 else {})} for n in range(100)]
                if "&page=2" in path:
                    return [{"number": 100, "body": run.marker(rule(1)), "state": "closed"}]
                if body is not None:
                    return {"number": 101}
                return {"number": 101, "title": "test", "body": "body", "html_url": "https://github.com/example/test/issues/101"}
        api = Api()
        issues = api.issues()
        self.assertEqual(len(issues), 100)
        self.assertEqual(issues[-1]["state"], "closed")
        self.assertTrue(all("state=all" in path for path, _ in api.calls))
        self.assertEqual(api.create("test", "body"), "https://github.com/example/test/issues/101")
        self.assertEqual(api.calls[-1][0], "/issues/101")

    def test_issue_retry_after_lost_response_preserves_quota_and_deduplication(self):
        class LostResponse(FakeGithub):
            def create(self, title, body):
                url = super().create(title, body)
                if len(self.writes) == 2:
                    raise OSError("response lost after issue creation")
                return url

        context = {"run_url": "https://example.test/run", "source_version": "v1", "rulec_version": "0.1.0"}
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            run.save(output / "differential.json", {"rules": [rule(n) for n in range(25)]})
            api = LostResponse()
            with self.assertRaisesRegex(OSError, "response lost"):
                run.publish(output, api, "schedule", "main", "main", context)
            self.assertEqual(len(run.load(output / "issues.json")["created"]), 1)
            self.assertEqual(len(api.existing), 2)
            # The server's second write survived even though verification did not.
            # A closed issue must still count against this run's quota on retry.
            api.existing[-1]["state"] = "closed"
            retry = run.publish(output, api, "schedule", "main", "main", context)
            self.assertEqual(retry["already_created_this_run"], 2)
            self.assertEqual(len(retry["created"]), 18)
            self.assertEqual(len(retry["deferred"]), 5)
            self.assertEqual(len(api.writes), 20)
            self.assertEqual(len({run.KEY_PATTERN.search(body).group() for _, body in api.writes}), 20)

    def test_baseline_first_workflow_and_missing_artifact_are_explicit(self):
        class Api:
            def request(self, path):
                raise urllib.error.HTTPError(path, 404, "not found", None, None)
        self.assertIsNone(run.baseline(None, Api(), "main"))
        class Expired:
            def request(self, path):
                if "/artifacts" in path:
                    return {"artifacts": [{"name": run.ARTIFACT, "expired": True}]}
                return {"workflow_runs": [{"id": 123456789, "head_branch": "main"}]}
        with self.assertRaisesRegex(ValueError, "no unexpired"):
            run.baseline(None, Expired(), "main")
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            run.save(output / "conversion.json", [report("et_open")])
            run.save(output / "differential.json", {"status": "completed", "errors": []})
            self.assertFalse(run.finish(output, baseline_error="직전 산출물 만료"))
            changes = run.load(output / "changes.json")
            self.assertTrue(changes["comparison_unavailable"])
            self.assertFalse(changes["first_run"])
            self.assertIn("직전 산출물 만료", (output / "summary.md").read_text())

    def test_baseline_reads_latest_scheduled_artifact_with_scoped_authentication(self):
        previous = [report("et_open")]
        data = io.BytesIO()
        with zipfile.ZipFile(data, "w") as archive:
            archive.writestr("conversion.json", json.dumps(previous))
        class Api:
            token = "test-token"
            def request(self, path):
                if "/artifacts" in path:
                    self.artifact_path = path
                    return {"artifacts": [{"name": run.ARTIFACT, "expired": False, "archive_download_url": "https://api.github.com/artifact"}]}
                self.runs_path = path
                return {"workflow_runs": [{"id": 123, "head_branch": "feature"}, {"id": 124, "head_branch": "main"}, {"id": 125, "head_branch": "main"}]}
        api = Api()
        with mock.patch.object(run, "fetch", return_value=data.getvalue()) as fetch:
            self.assertEqual(run.baseline(None, api, "main"), previous)
        self.assertIn("event=schedule&status=success", api.runs_path)
        self.assertIn("branch=main", api.runs_path)
        self.assertEqual(api.artifact_path, "/actions/runs/124/artifacts?per_page=100")
        fetch.assert_called_once_with("https://api.github.com/artifact", "test-token")

    def test_missing_coverage_and_excluded_pcaps_fail_but_mismatches_do_not(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            run.save(output / "conversion.json", [report("et_open"), report("sigma_hq"), report("sigma_hq_emerging")])
            run.save(output / "differential.json", {"status": "completed", "counts": {"suricata_only": 5}, "errors": []})
            self.assertFalse(run.finish(output))
            for error in ["no compared rules in scopes: dns", "one or more pcaps excluded"]:
                run.save(output / "differential.json", {"status": "completed", "errors": [error]})
                self.assertTrue(run.finish(output))
                self.assertIn(error, (output / "summary.md").read_text())

    def test_all_rejected_scope_is_named_with_reasons_without_failing(self):
        with tempfile.TemporaryDirectory() as name:
            output = Path(name)
            run.save(output / "conversion.json", [report("et_open")])
            run.save(output / "differential.json", {
                "status": "completed", "errors": [], "missing_scopes": [],
                "coverage": {"ssh_server_banner": []},
                "no_comparable_rules": {"ssh_server_banner": [
                    {"sid": "91", "reason": "needs_state"},
                    {"sid": "92", "reason": "unsupported_regex"},
                ]},
            })
            self.assertFalse(run.finish(output))
            self.assertFalse(run.load(output / "status.json")["failed"])
            summary = (output / "summary.md").read_text()
            self.assertIn("ssh_server_banner: 견줄 규칙 없음", summary)
            self.assertIn("91 (needs_state)", summary)
            self.assertIn("92 (unsupported_regex)", summary)


if __name__ == "__main__":
    unittest.main()
