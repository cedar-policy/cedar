#!/usr/bin/env python3
"""Helpers for the "Create release tags and GitHub releases" workflow.

Usage:
    release-tags.py check-ci <sha> [--force]
    release-tags.py check-tags <sha> <tag>...
    release-tags.py create-tags <sha> <tag>...
    release-tags.py release-notes <changelog> <version> <intro>

check-ci       Finds the merged PR that produced <sha> and checks that all check runs and
               commit statuses on that PR's head commit succeeded (or were skipped or neutral).
               CI only runs on pull requests in this repo, so <sha> itself has no checks.
               Fails if a check is not green, unless --force is given, in which case it warns.
check-tags     Fails if any <tag> exists on a commit other than <sha>.
create-tags    Creates each missing <tag> on <sha> as a lightweight tag. A tag that already
               exists on <sha> is left alone. Fails if a tag exists on another commit.
release-notes  Prints <intro>, a blank line, then the body of the `## [<version>]` section of
               <changelog>. Fails if there is no such section or it has no entries.

The GitHub commands use $GITHUB_REPOSITORY, $GITHUB_API_URL and the token in $GH_TOKEN.
"""
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

# Check run conclusions that do not block a release.
GREEN_CONCLUSIONS = {"success", "skipped", "neutral"}


def fail(msg):
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def api(method, path, body=None):
    """Calls the GitHub REST API. Returns (status, decoded JSON body or None)."""
    url = os.environ.get("GITHUB_API_URL", "https://api.github.com") + path
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("X-GitHub-Api-Version", "2022-11-28")
    req.add_header("Authorization", f"Bearer {os.environ['GH_TOKEN']}")
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            raw = resp.read()
            return resp.status, json.loads(raw) if raw else None
    except urllib.error.HTTPError as e:
        raw = e.read()
        try:
            return e.code, json.loads(raw)
        except json.JSONDecodeError:
            return e.code, None


def api_ok(method, path, body=None):
    status, data = api(method, path, body)
    if status >= 300:
        fail(f"GitHub API {method} {path} returned {status}: {data}")
    return data


def repo():
    return os.environ["GITHUB_REPOSITORY"]


def tag_commit(tag):
    """Returns the commit a tag points to, or None if the tag does not exist."""
    status, data = api("GET", f"/repos/{repo()}/commits/{urllib.parse.quote('refs/tags/' + tag, safe='/')}")
    if status in (404, 422):
        return None
    if status >= 300:
        fail(f"Could not look up tag {tag}: {status} {data}")
    return data["sha"]


def check_ci(sha, force):
    pulls = api_ok("GET", f"/repos/{repo()}/commits/{sha}/pulls")
    merged = [p for p in pulls if p.get("merged_at") and p.get("merge_commit_sha") == sha]
    if not merged:
        merged = [p for p in pulls if p.get("merged_at")]
    if not merged:
        report(
            [f"no merged pull request found for {sha}, so there is no CI run to check (was it pushed directly?)"],
            force,
        )
        return
    pr = merged[0]
    head = pr["head"]["sha"]
    print(f"{sha} was merged by PR #{pr['number']} ({pr['html_url']}); checking CI on its head commit {head}")

    runs = []
    page = 1
    while True:
        data = api_ok("GET", f"/repos/{repo()}/commits/{head}/check-runs?per_page=100&page={page}")
        runs += data["check_runs"]
        if len(runs) >= data["total_count"] or not data["check_runs"]:
            break
        page += 1
    statuses = api_ok("GET", f"/repos/{repo()}/commits/{head}/status")["statuses"]

    problems = []
    for run in sorted(runs, key=lambda r: r["name"]):
        state = run["conclusion"] if run["status"] == "completed" else run["status"]
        print(f"  check  {state:<16} {run['name']}")
        if run["status"] != "completed" or run["conclusion"] not in GREEN_CONCLUSIONS:
            problems.append(f"check '{run['name']}' is {state}: {run['html_url']}")
    for st in statuses:
        print(f"  status {st['state']:<16} {st['context']}")
        if st["state"] != "success":
            problems.append(f"status '{st['context']}' is {st['state']}: {st.get('target_url')}")
    if not runs and not statuses:
        problems.append(f"PR #{pr['number']} has no checks on its head commit {head}")
    report(problems, force)


def report(problems, force):
    if not problems:
        print("CI is green.")
        return
    level = "warning" if force else "error"
    for p in problems:
        print(f"::{level}::{p}")
    if force:
        print("::warning::Continuing because 'force' is set.")
    else:
        fail("CI on the release branch head is not green. Fix it, or re-run with 'force' if the failures are expected.")


def check_tags(sha, tags):
    conflicts = []
    for tag in tags:
        commit = tag_commit(tag)
        if commit is None:
            print(f"{tag}: does not exist yet, will be created on {sha}")
        elif commit == sha:
            print(f"::notice::{tag} already exists on {sha}; nothing to do for it.")
        else:
            conflicts.append(f"tag {tag} already exists on {commit}, not on the release branch head {sha}")
    for c in conflicts:
        print(f"::error::{c}")
    if conflicts:
        sys.exit(1)


def create_tags(sha, tags):
    check_tags(sha, tags)
    for tag in tags:
        if tag_commit(tag) is not None:
            continue
        status, data = api("POST", f"/repos/{repo()}/git/refs", {"ref": f"refs/tags/{tag}", "sha": sha})
        if status >= 300:
            # Someone may have created it in the meantime; accept that if it is on the same commit.
            if tag_commit(tag) == sha:
                print(f"::notice::{tag} was created on {sha} concurrently; nothing to do for it.")
                continue
            fail(f"Could not create tag {tag} on {sha}: {status} {data}")
        print(f"Created tag {tag} on {sha}")


def release_notes(changelog, version, intro):
    path = Path(changelog)
    if not path.exists():
        fail(f"{changelog} not found")
    text = path.read_text()
    heading = re.compile(rf"^## \[{re.escape(version)}\].*$", re.MULTILINE)
    matches = list(heading.finditer(text))
    if len(matches) != 1:
        fail(f"expected exactly one heading for version {version} in {changelog}, found {len(matches)}")
    rest = text[matches[0].end() :]
    end = re.search(r"^## ", rest, re.MULTILINE)
    body = (rest[: end.start()] if end else rest).strip()
    # A section that only has the language version line has no entries.
    entries = re.sub(r"^Cedar Language Version:.*$", "", body, flags=re.MULTILINE).strip()
    if not entries:
        fail(f"the section for {version} in {changelog} is empty; add the changelog entries on main first")
    print(f"{intro}\n\n{body}")


def main():
    args = sys.argv[1:]
    if not args:
        fail(__doc__)
    cmd, rest = args[0], args[1:]
    if cmd == "check-ci" and len(rest) in (1, 2) and (len(rest) == 1 or rest[1] == "--force"):
        check_ci(rest[0], force=len(rest) == 2)
    elif cmd == "check-tags" and len(rest) >= 2:
        check_tags(rest[0], rest[1:])
    elif cmd == "create-tags" and len(rest) >= 2:
        create_tags(rest[0], rest[1:])
    elif cmd == "release-notes" and len(rest) == 3:
        release_notes(*rest)
    else:
        fail(f"invalid arguments: {' '.join(args)}\n{__doc__}")


if __name__ == "__main__":
    main()
