#!/usr/bin/env python3
"""Usage: wait-for-published.py (crates|npm) <name>=<version>... [--initial-delay SECONDS] [--interval SECONDS] [--timeout SECONDS]

Polls the crates.io sparse index (`crates`, https://index.crates.io) or the npm registry (`npm`) until every
<name>=<version> is published, or until the timeout expires.
The first poll happens after the initial delay, since a just-published
version usually takes a little while to show up.
Fails, listing every package that is still missing, if the timeout expires.
A yanked crate version counts as missing.

Examples:
    wait-for-published.py crates cedar-policy-core=4.15.0 cedar-policy=4.15.0
    wait-for-published.py npm @cedar-policy/cedar-wasm=4.15.0 --timeout 600
"""
import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# crates.io rejects requests without a User-Agent and asks for one that identifies the caller.
# See https://crates.io/data-access
USER_AGENT = "cedar-policy/cedar publish verification (https://github.com/cedar-policy/cedar)"


def fetch(url, accept):
    """Returns the response body as text, or None on a 404."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept})
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise


def fetch_json(url):
    """Returns the decoded JSON body, or None on a 404."""
    body = fetch(url, "application/json")
    return None if body is None else json.loads(body)


def sparse_index_path(name):
    """Returns the path of a crate in the sparse index, e.g. cedar-policy -> ce/da/cedar-policy.
    See https://doc.rust-lang.org/cargo/reference/registry-index.html#index-files"""
    name = name.lower()
    if len(name) <= 2:
        return f"{len(name)}/{name}"
    if len(name) == 3:
        return f"3/{name[0]}/{name}"
    return f"{name[:2]}/{name[2:4]}/{name}"


def crate_status(name, version):
    """Returns None if the crate version is published and not yanked, else the reason it is not."""
    # The index file has one JSON object per line, one line per published version.
    body = fetch(f"https://index.crates.io/{sparse_index_path(name)}", "text/plain")
    if body is None:
        return "not found"
    for line in body.splitlines():
        if not line.strip():
            continue
        entry = json.loads(line)
        if entry.get("vers") == version:
            return "yanked" if entry.get("yanked") else None
    return "not found"


def npm_status(name, version):
    """Returns None if the npm package version is published, else the reason it is not."""
    # Scoped names keep the '@' and encode the '/', e.g. @cedar-policy%2Fcedar-wasm.
    url = f"https://registry.npmjs.org/{urllib.parse.quote(name, safe='@')}/{urllib.parse.quote(version)}"
    body = fetch_json(url)
    if body is None:
        return "not found"
    if body.get("version") != version:
        return f"registry returned version {body.get('version')!r}"
    return None


def parse_package(arg):
    name, sep, version = arg.rpartition("=")
    if not sep or not name or not version:
        raise argparse.ArgumentTypeError(f"expected <name>=<version>, got '{arg}'")
    return name, version


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("registry", choices=["crates", "npm"])
    parser.add_argument("packages", nargs="+", type=parse_package, metavar="name=version")
    parser.add_argument(
        "--initial-delay", type=int, default=60, help="seconds to wait before the first poll (default: 60)"
    )
    parser.add_argument("--interval", type=int, default=30, help="seconds between polls (default: 30)")
    parser.add_argument(
        "--timeout", type=int, default=600, help="seconds to wait in total, including the initial delay (default: 600)"
    )
    args = parser.parse_args()

    status = crate_status if args.registry == "crates" else npm_status
    deadline = time.monotonic() + args.timeout
    if args.initial_delay > 0:
        print(f"Waiting {args.initial_delay}s before the first poll")
        time.sleep(args.initial_delay)
    pending = dict.fromkeys(args.packages, "not checked")
    while True:
        for name, version in list(pending):
            try:
                reason = status(name, version)
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as e:
                # Transient registry or network errors are retried until the deadline.
                reason = f"request failed: {e}"
            if reason is None:
                print(f"{name} {version} is published on {args.registry}")
                del pending[(name, version)]
            else:
                pending[(name, version)] = reason
        if not pending:
            return
        if time.monotonic() >= deadline:
            break
        waiting = ", ".join(f"{n} {v} ({r})" for (n, v), r in pending.items())
        print(f"Waiting {args.interval}s for: {waiting}")
        time.sleep(args.interval)

    for (name, version), reason in pending.items():
        print(f"::error::{name} {version} is not published on {args.registry} after {args.timeout}s: {reason}", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
