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


def rule(sid, rev=1, mark=None):
    return {"sid": str(sid), "rev": rev, "msg": "test message", "classification": "suricata_only", "input_limit": mark == "input", "threshold": mark == "threshold", "pairs": [{"key": {"pcap": "public", "flow": 42}, "classification": "suricata_only", "evidence": [{"tuple": ["10.0.0.1", 1234, "1.2.3.4", 80, 6], "kind": "Http", "fields": ["uri"]}]}]}


def report(source, error=None):
    return {"source": source, "error": error, "input_count": 2, "accepted_ids": ["1"], "summary": {"source_version": {"version": "v1"}, "rulec_version": "0.1.0", "accepted": {"EtSignature": 1}, "dropped": {"needs_state": ["2"]}}}


class DailyTests(unittest.TestCase):
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

    def test_public_manifest_and_reproducible_synthetic_capture(self):
        for entry in run.load(run.HERE / "pcaps.json"):
            self.assertTrue(all(entry.get(k) for k in ["name", "url", "sha256", "source", "license", "coverage"]))
            self.assertRegex(entry["sha256"], r"^[a-f0-9]{64}$")
        fixture = (run.HERE / "pcaps/protocol-probes.pcap").read_bytes()
        self.assertEqual(make_probes.generate(), fixture)
        self.assertEqual(hashlib.sha256(fixture).hexdigest(), run.load(run.HERE / "pcaps.json")[0]["sha256"])

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
                "status": "completed", "errors": [],
                "coverage": {"ssh_server_banner": []},
                "no_comparable_rules": {"ssh_server_banner": [
                    {"sid": "91", "reason": "needs_state"},
                    {"sid": "92", "reason": "unsupported_regex"},
                ]},
            })
            self.assertFalse(run.finish(output))
            summary = (output / "summary.md").read_text()
            self.assertIn("ssh_server_banner: 비교 가능한 규칙 없음 (no comparable rule)", summary)
            self.assertIn("91 (needs_state)", summary)
            self.assertIn("92 (unsupported_regex)", summary)


if __name__ == "__main__":
    unittest.main()
