#!/usr/bin/env python3
"""Usage: set-changelog-release-date.py <changelog> <version> <date>

Replaces the placeholder after the heading for <version> in <changelog>
(e.g. `## [4.15.0] - Coming soon`) with <date> (e.g. `## [4.15.0] - 2026-11-16`).

The placeholder heading is written by the cargo-release `pre-release-replacements`
in cedar-policy/Cargo.toml and cedar-policy-symcc/Cargo.toml (run by
scripts/new_minor.sh). Any non-date text after the version is accepted as the
placeholder, since it is sometimes edited by hand (e.g. to "Coming Soon").

Does nothing if the heading already has a date. Fails if there is no heading
for <version>.
"""
import re
import sys
from pathlib import Path

DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


def fail(msg):
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <changelog> <version> <date>", file=sys.stderr)
        sys.exit(1)

    changelog = Path(sys.argv[1])
    version = sys.argv[2]
    date = sys.argv[3]

    if not DATE_PATTERN.match(date):
        fail(f"date must be of the form YYYY-MM-DD, got '{date}'")
    if not changelog.exists():
        fail(f"{changelog} not found")

    # Matches the whole heading line for this version, e.g. `## [4.15.0] - Coming Soon`.
    heading = re.compile(rf"^## \[{re.escape(version)}\] - (?P<rest>.*)$", re.MULTILINE)
    text = changelog.read_text()
    matches = list(heading.finditer(text))
    if len(matches) != 1:
        fail(f"expected exactly one heading for version {version} in {changelog}, found {len(matches)}")

    match = matches[0]
    rest = match.group("rest").strip()
    if DATE_PATTERN.match(rest):
        print(f"::notice::{changelog} already has a date for {version}: {rest}")
        return

    new_heading = f"## [{version}] - {date}"
    changelog.write_text(text[: match.start()] + new_heading + text[match.end() :])
    print(f"{changelog}: '{match.group(0)}' -> '{new_heading}'")


if __name__ == "__main__":
    main()
