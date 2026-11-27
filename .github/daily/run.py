#!/usr/bin/env python3
"""Network/process boundary for the offline Rust example; standard library only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import urllib.error
import urllib.request
import urllib.parse
import zipfile

HERE = Path(__file__).resolve().parent
HOME_NET = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]
ARTIFACT = "daily-results"
KEY_PATTERN = re.compile(r"<!-- rulec-differential:sid=\d+;rev=(?:\d+|None) -->")


def save(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    temporary.replace(path)


def load(path):
    return json.loads(Path(path).read_text())


def failure_reason(error):
    if isinstance(error, urllib.error.HTTPError):
        return f"HTTP {error.code} ({error.reason})"
    if isinstance(error, urllib.error.URLError):
        return f"network error: {error.reason}"
    return f"{type(error).__name__}: {error}"


class PublicDownloadRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, new_url):
        redirected = super().redirect_request(request, response, code, message, headers, new_url)
        if redirected is not None and urllib.parse.urlsplit(new_url)[:2] != urllib.parse.urlsplit(request.full_url)[:2]:
            redirected.remove_header("Authorization")
        return redirected


def fetch(url, token=None):
    github_api = urllib.parse.urlsplit(url)[:2] == ("https", "api.github.com")
    headers = {"User-Agent": "rulec-daily", "Accept": "application/vnd.github+json"} if github_api else {"User-Agent": "rulec-daily"}
    if token and github_api:
        headers["Authorization"] = "Bearer " + token
    opener = urllib.request.build_opener(PublicDownloadRedirect())
    with opener.open(urllib.request.Request(url, headers=headers), timeout=120) as response:
        return response.read()


def download_sources(work, get=fetch):
    work.mkdir(parents=True, exist_ok=True)
    sources = []
    for name in ("et_open", "sigma_hq", "sigma_hq_emerging"):
        item = {"source": name, "path": None, "version": None, "error": None}
        try:
            if name == "et_open":
                base = "https://rules.emergingthreats.net/open/suricata-7.0.3/"
                item["version"] = str(int(get(base + "version.txt").strip()))
                data = get(base + "emerging.rules.tar.gz")
                path = work / "et.tar.gz"
            elif name == "sigma_hq":
                release = json.loads(get("https://api.github.com/repos/SigmaHQ/sigma/releases/latest"))
                item["version"] = release["tag_name"]
                asset = next((a for a in release["assets"] if a["name"] == "sigma_all_rules.zip"), None)
                if asset is None:
                    raise ValueError("latest release has no sigma_all_rules.zip asset")
                data = get(asset["browser_download_url"])
                path = work / "sigma.zip"
            else:
                commits = json.loads(get("https://api.github.com/repos/SigmaHQ/sigma/commits?path=rules-emerging-threats&per_page=1"))
                sha = commits[0]["sha"]
                if not re.fullmatch(r"[0-9a-fA-F]{40}", sha):
                    raise ValueError("invalid upstream commit SHA")
                item["version"] = sha
                data = get(f"https://github.com/SigmaHQ/sigma/archive/{sha}.zip")
                path = work / "emerging.zip"
            path.write_bytes(data)
            item["path"] = path.name
        except Exception as error:  # One source must not prevent the others.
            item["error"] = "download failed: " + failure_reason(error)
        sources.append(item)
    save(work / "sources.json", sources)
    return sources


def checked_pcap(entry, work, get=fetch):
    url = entry["url"]
    if "{revision}" in url and not os.environ.get("SOURCE_REVISION"):
        data = (HERE / "pcaps" / Path(entry["bundled_path"]).name).read_bytes()
    else:
        url = url.format(repository=os.environ.get("SOURCE_REPOSITORY", "aicers/rulec"), revision=os.environ.get("SOURCE_REVISION", "main"))
        data = get(url)
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError("pcap SHA-256 mismatch")
    path = work / (entry["name"] + ".pcap")
    path.write_bytes(data)
    return path


def included_et(name):
    while name.startswith("./"):
        name = name[2:]
    if not name.startswith("rules/"):
        return False
    name = name[6:]
    return ("/" not in name and name.endswith(".rules") and not name.startswith("threatview") and name not in {
        "emerging-retired.rules", "botcc.rules", "botcc.portgrouped.rules", "ciarmy.rules", "compromised.rules", "drop.rules", "dshield.rules", "tor.rules"})


def run_suricata(work, output, manifest=HERE / "pcaps.json", get=fetch, execute=subprocess.run):
    (output / "differential.json").unlink(missing_ok=True)
    reports = load(output / "conversion.json")
    et = next(r for r in reports if r["source"] == "et_open")
    if et["error"]:
        save(work / "pcap-runs.json", [])
        return  # Rust compare writes the explicit skip report.
    version = execute(["suricata", "-V"], capture_output=True, text=True, check=True).stdout.strip()
    print(version, flush=True)
    match = re.search(r"\bversion ([0-9.]+)\b", version)
    if not match or match[1] != "7.0.3":
        raise ValueError("expected exactly Suricata 7.0.3")
    archive = work / "et.tar.gz"
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    config = ["-c", "/etc/suricata/suricata.yaml", "--include", str(HERE / "suricata.yaml"), "--set", "vars.address-groups.HOME_NET=[" + ",".join(HOME_NET) + "]"]
    effective = execute(["suricata", *config, "--dump-config"], capture_output=True, text=True, check=True).stdout
    home_net = re.search(r"^vars\.address-groups\.HOME_NET = \[([^\]]*)\]$", effective, re.MULTILINE)
    if not home_net or [part.strip() for part in home_net[1].split(",")] != HOME_NET:
        raise ValueError("Suricata effective HOME_NET does not match the comparison networks")
    save(work / "suricata.json", {"version": match[1], "et_archive_sha256": digest, "home_net": [part.strip() for part in home_net[1].split(",")]})
    # Never extract archive paths. The same bytes used by rulec supply only the
    # documented included rule files to Suricata. These files remain ephemeral.
    rules = work / "suricata.rules"
    with tarfile.open(archive, "r:gz") as tar, rules.open("wb") as target:
        for entry in tar:
            if entry.isfile() and included_et(entry.name):
                with tar.extractfile(entry) as source:
                    target.write(source.read())
                    target.write(b"\n")
    runs = []
    for entry in load(manifest):
        item = {"name": entry["name"], "eve": None, "error": None}
        try:
            path = checked_pcap(entry, work, get)
            log = work / entry["name"]
            log.mkdir(parents=True, exist_ok=True)
            command = ["suricata", "--runmode", "single", *config, "--init-errors-fatal", "-S", str(rules.resolve()), "-r", str(path.resolve()), "-l", str(log.resolve()), "-k", "none"]
            result = execute(command, capture_output=True, text=True)
            # Suricata diagnostics may contain entire rejected signatures. Do not
            # copy them into results, console logs, or uploaded artifacts.
            if result.returncode:
                raise RuntimeError(f"Suricata exited {result.returncode}")
            item["eve"] = str((log / "eve.json").relative_to(work))
            if not (log / "eve.json").is_file():
                raise RuntimeError("missing EVE output")
        except Exception as error:
            item["error"] = str(error) if isinstance(error, (ValueError, RuntimeError)) else "pcap processing failed: " + failure_reason(error)
        runs.append(item)
        save(work / "pcap-runs.json", runs)


def delta(current, previous):
    if previous is None:
        return {"first_run": True, "message": "직전 성공한 예약 실행 결과가 없습니다."}
    prior = {r["source"]: r for r in previous}
    changes = []
    for item in current:
        old = prior.get(item["source"])
        if item["error"] or not old or old["error"]:
            changes.append({"source": item["source"], "error": item["error"], "baseline_unavailable": not old or bool(old["error"])})
            continue
        before, after = old["summary"], item["summary"]
        def counts(summary, field):
            return {k: len(v) if isinstance(v, list) else v for k, v in summary[field].items()}
        def changes_in(field):
            a, b = counts(before, field), counts(after, field)
            return {key: b.get(key, 0) - a.get(key, 0) for key in sorted(a.keys() | b.keys())}
        old_drop = {sid for ids in before["dropped"].values() for sid in ids}
        new_drop = {sid for ids in after["dropped"].values() for sid in ids}
        changes.append({"source": item["source"], "source_version": {"before": before["source_version"], "after": after["source_version"]}, "rulec_version": {"before": before["rulec_version"], "after": after["rulec_version"]}, "accepted_delta": changes_in("accepted"), "dropped_delta": changes_in("dropped"), "newly_dropped_ids": sorted(new_drop - old_drop), "newly_accepted_ids": sorted(set(item["accepted_ids"]) - set(old["accepted_ids"]))})
    return {"first_run": False, "sources": changes}


class Github:
    def __init__(self, repository, token):
        self.base = "https://api.github.com/repos/" + repository
        self.token = token

    def request(self, path, body=None):
        request = urllib.request.Request(self.base + path, data=None if body is None else json.dumps(body).encode(), headers={"Authorization": "Bearer " + self.token, "Accept": "application/vnd.github+json", "User-Agent": "rulec-daily", "X-GitHub-Api-Version": "2022-11-28"})
        with urllib.request.urlopen(request, timeout=120) as response:
            return json.load(response)

    def issues(self):
        # REST issues includes PRs. Exclude them; inspect open AND closed issues.
        result = []
        page = 1
        while True:
            items = self.request(f"/issues?state=all&per_page=100&page={page}")
            result.extend(i for i in items if "pull_request" not in i)
            if len(items) < 100:
                return result
            page += 1

    def create(self, title, body):
        created = self.request("/issues", {"title": title, "body": body})
        # Verify identity/type and persisted content after the write.
        verified = self.request("/issues/" + str(created["number"]))
        if "pull_request" in verified or verified["title"] != title or verified["body"] != body or "/issues/" not in verified["html_url"]:
            raise ValueError("created issue verification failed")
        return verified["html_url"]


def marker(rule):
    return f'<!-- rulec-differential:sid={rule["sid"]};rev={rule["rev"]} -->'


def issue_plan(rules, existing, limit=20):
    seen = {match.group(0) for issue in existing for match in KEY_PATTERN.finditer(issue.get("body") or "")}
    planned, deferred = [], []
    for rule in rules:
        key = marker(rule)
        if rule["classification"] == "equal" or rule["input_limit"] or rule["threshold"] or key in seen:
            continue
        seen.add(key)
        (planned if len(planned) < limit else deferred).append(rule)
    return planned, deferred


def issue_body(rule, context):
    pairs = [{"pcap": pair["key"]["pcap"], "flow_id": pair["key"]["flow"], "classification": pair["classification"], "records": [{"five_tuple": e["tuple"], "kind": e["kind"], "true_fields": e["fields"]} for e in pair["evidence"]]} for pair in rule["pairs"]]
    # All values are serialized in a fence, avoiding incidental issue references
    # or Markdown injection from upstream msg values. No signature text is used.
    details = {"sid": rule["sid"], "rev": rule["rev"], "msg": rule["msg"], "분류": rule["classification"], "어긋난 쌍": pairs, "발견한 실행": context["run_url"], "원천 판": context["source_version"], "rulec 판": context["rulec_version"]}
    data = json.dumps(details, ensure_ascii=False, indent=2).replace("`", "\\u0060")
    return f'{marker(rule)}\n\nSuricata 7.0.3과 rulec의 판정이 다릅니다. 변환기 수정 또는 차단 목록 변경은 별도 PR로 검토합니다.\n\n```json\n{data}\n```\n'


def publish(output, api, event, branch, default_branch, context):
    differential = load(output / "differential.json")
    existing = api.issues()
    # Attempts of one workflow run share its run URL and its twenty-issue quota.
    run_url = json.dumps(context["run_url"], ensure_ascii=False)
    earlier = [issue for issue in existing if KEY_PATTERN.search(issue.get("body") or "") and run_url in (issue.get("body") or "")]
    remaining = max(0, 20 - len(earlier))
    planned, deferred = issue_plan(differential.get("rules", []), existing, limit=remaining)
    allowed = event == "schedule" and branch == default_branch
    result = {"publishing_enabled": allowed, "planned": [{"sid": r["sid"], "rev": r["rev"], "title": f'ET 규칙 sid {r["sid"]} rev {r["rev"]} 판정 차이', "body": issue_body(r, context)} for r in planned], "deferred": [{"sid": r["sid"], "rev": r["rev"]} for r in deferred], "created": []}
    result["already_created_this_run"] = len(earlier)
    result["previously_created_urls"] = [issue["html_url"] for issue in earlier if issue.get("html_url")]
    save(output / "issues.json", result)
    if allowed:
        for candidate in result["planned"]:
            # Re-query before each write to avoid duplicates if another actor filed
            # an issue after the plan. Workflow concurrency serializes our runs.
            rule = {"sid": candidate["sid"], "rev": candidate["rev"]}
            if any(marker(rule) in (i.get("body") or "") for i in api.issues()):
                continue
            result["created"].append(api.create(candidate["title"], candidate["body"]))
            save(output / "issues.json", result)
    return result


def baseline(output, api, default_branch):
    try:
        runs = api.request("/actions/workflows/daily.yml/runs?event=schedule&status=success&per_page=100&branch=" + urllib.parse.quote(default_branch, safe=""))
    except urllib.error.HTTPError as error:
        if error.code == 404:
            return None  # A new PR workflow is not registered on the default branch yet.
        raise
    candidates = [r for r in runs["workflow_runs"] if r["head_branch"] == default_branch and str(r["id"]) != os.environ.get("GITHUB_RUN_ID")]
    if not candidates:
        return None
    # Never silently substitute an older run if the last successful run's
    # artifact expired or cannot be read.
    artifacts = api.request(f'/actions/runs/{candidates[0]["id"]}/artifacts?per_page=100')["artifacts"]
    artifact = next((a for a in artifacts if a["name"] == ARTIFACT and not a["expired"]), None)
    if artifact is None:
        raise ValueError("last successful scheduled run has no unexpired daily-results artifact")
    data = fetch(artifact["archive_download_url"], api.token)
    import io
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return json.loads(archive.read("conversion.json"))


def finish(output, previous=None, baseline_error=None):
    reports = load(output / "conversion.json")
    differential = load(output / "differential.json")
    changes = delta(reports, previous)
    if baseline_error:
        changes = {"first_run": False, "comparison_unavailable": True, "error": baseline_error}
    save(output / "changes.json", changes)
    failed = any(r["error"] for r in reports) or bool(differential.get("errors"))
    lines = ["## 원천 매일 변환과 Suricata 차분 시험", "", "| 원천 | 입력 | 모델별 받아들임 | 이유별 버림 | 상태 |", "| --- | ---: | --- | --- | --- |"]
    for report in reports:
        summary = report["summary"] or {"accepted": {}, "dropped": {}}
        accepted = ", ".join(f"{k}: {v}" for k, v in summary["accepted"].items())
        dropped = ", ".join(f"{k}: {len(v)}" for k, v in summary["dropped"].items())
        lines.append(f'| {report["source"]} | {report["input_count"]} | {accepted} | {dropped} | {report["error"] or "성공"} |')
    lines += ["", changes.get("message", changes.get("error", "직전 성공한 예약 실행과 비교했습니다.")), "", f'Suricata: {differential.get("suricata_version", "미실행")}', f'차분 상태: {differential["status"]} {differential.get("reason") or ""}', "", "분류: " + json.dumps(differential.get("counts", {}), ensure_ascii=False), ""]
    for scope, rules in differential.get("coverage", {}).items():
        rejected = differential.get("no_comparable_rules", {}).get(scope)
        if rejected:
            lines.append(f'- {scope}: 견줄 규칙 없음; ' + ", ".join(f'{r["sid"]} ({r["reason"]})' for r in rejected))
        else:
            lines.append(f'- {scope}: ' + (", ".join(f'{r["sid"]} ({r["classification"]})' for r in rules) or "견준 규칙 없음"))
    for excluded in differential.get("excluded_pcaps", []):
        lines.append(f'- 제외한 pcap {excluded["pcap"]}: {excluded["reason"]}')
    for error in differential.get("errors", []):
        lines.append("- 실패: " + error)
    save(output / "status.json", {"failed": failed})
    summary = "\n".join(lines) + "\n"
    (output / "summary.md").write_text(summary)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a") as target:
            target.write(summary)
    return failed


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=["download", "suricata", "finish", "issues"])
    parser.add_argument("--work", type=Path, default=Path("daily-work"))
    parser.add_argument("--output", type=Path, default=Path("daily-results"))
    args = parser.parse_args()
    if args.command == "download":
        token = os.environ.get("GH_TOKEN")
        download_sources(args.work, lambda url: fetch(url, token))
    elif args.command == "suricata":
        try:
            run_suricata(args.work, args.output)
        except Exception as error:
            save(args.output / "differential.json", {"status": "failed", "reason": str(error), "errors": [str(error)], "rules": [], "counts": {}, "coverage": {}})
    elif args.command == "finish":
        previous, error = None, None
        if os.environ.get("GITHUB_REPOSITORY"):
            try:
                api = Github(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
                previous = baseline(args.output, api, os.environ["DEFAULT_BRANCH"])
            except Exception as cause:
                error = "직전 실행 산출물을 읽지 못했습니다: " + failure_reason(cause)
        finish(args.output, previous, error)
    else:
        reports = load(args.output / "conversion.json")
        et = next(r for r in reports if r["source"] == "et_open")
        context = {"run_url": os.environ["RUN_URL"], "source_version": (et["summary"] or {}).get("source_version"), "rulec_version": (et["summary"] or {}).get("rulec_version")}
        api = Github(os.environ["GITHUB_REPOSITORY"], os.environ["GH_TOKEN"])
        publish(args.output, api, os.environ["EVENT_NAME"], os.environ["BRANCH_NAME"], os.environ["DEFAULT_BRANCH"], context)


if __name__ == "__main__":
    main()
