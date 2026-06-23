#!/usr/bin/env python3
"""Check that a crate's version matches the expected version."""
import sys
import tomllib
from pathlib import Path


def fail(msg):
    print(f"::error::{msg}", file=sys.stderr)
    sys.exit(1)


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <crate-dir> <expected-version>", file=sys.stderr)
        sys.exit(1)

    crate_dir = Path(sys.argv[1])
    expected = sys.argv[2]

    crate_toml = crate_dir / "Cargo.toml"
    if not crate_toml.exists():
        fail(f"{crate_toml} not found")

    with open(crate_toml, "rb") as f:
        crate_data = tomllib.load(f)

    pkg_version = crate_data.get("package", {}).get("version")
    if pkg_version is None:
        fail(f"No version field in {crate_toml}")

    if isinstance(pkg_version, dict) and pkg_version.get("workspace") is True:
        workspace_toml = crate_dir.parent / "Cargo.toml"
        if not workspace_toml.exists():
            fail(f"{workspace_toml} not found")
        with open(workspace_toml, "rb") as f:
            workspace_data = tomllib.load(f)
        version = workspace_data.get("workspace", {}).get("package", {}).get("version")
        if version is None:
            fail(f"No workspace.package.version in {workspace_toml}")
        source = str(workspace_toml)
    else:
        version = pkg_version
        source = str(crate_toml)

    if version != expected:
        fail(f"{crate_dir} version mismatch: expected '{expected}' but {source} has '{version}'")


if __name__ == "__main__":
    main()
