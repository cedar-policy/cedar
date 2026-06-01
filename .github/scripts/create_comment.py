import json
import itertools
import argparse
from collections import defaultdict
from typing import TypedDict

TEMPLATE = """\
# Coverage Report
Head Commit: ```{head_sha}```

Base Commit: ```{base_sha}```

[Download the full coverage report.]({report_url})

## Coverage of Added or Modified Lines of Rust Code
{mod_summary}

<details>
<summary><b>Details</b></summary>

| File | Status | Covered | Coverage | Missed Lines |
|:-----|:------:|:-------:|---------:|:-------------|
{mod_table}
</details>

## Coverage of All Lines of Rust Code
{all_summary}

<details>
<summary><b>Details</b></summary>

| Package | Status | Covered | Coverage | Base Coverage |
|:--------|:------:|:-------:|---------:|--------------:|
{all_table}
</details>
"""


class LineCoverage(TypedDict):
    package: str
    file_name: str
    line_number: int
    hit_count: int
    was_modified: bool


def parse_line(line) -> LineCoverage:
    return LineCoverage(
        package=sanitize_name(line["package"]),
        file_name=sanitize_name(line["file_name"]),
        line_number=int(line["line_number"]),
        hit_count=int(line["hit_count"]),
        was_modified=bool(line["was_modified"]),
    )


def sanitize_name(name: str) -> str:
    """Only allow alphanumeric chars and safe path characters."""
    allowed = set("-_/.")
    return "".join(c for c in str(name) if c.isalnum() or c in allowed)


def get_status_icon(coverage: float, required_coverage: float) -> str:
    if required_coverage == -1:
        return ":white_circle:"
    elif coverage >= required_coverage:
        return ":green_circle:"
    elif coverage >= (required_coverage - 0.1):
        return ":yellow_circle:"
    else:
        return ":red_circle:"


def group_lines(lines: list[LineCoverage], key: str) -> dict[str, list[LineCoverage]]:
    groups = defaultdict(list)
    for line in lines:
        groups[line[key]].append(line)
    return dict(sorted(groups.items()))


def format_ranges(numbers: list[int]) -> str:
    numbers = sorted(set(numbers))
    if not numbers:
        return ""
    parts = []
    # Group elements by the difference between the value and its index
    for _, group in itertools.groupby(enumerate(numbers), lambda t: t[1] - t[0]):
        group = list(group)
        # Take the value of the first and last elements of the group
        start, end = group[0][1], group[-1][1]
        parts.append(str(start) if start == end else f"{start}-{end}")
    return ", ".join(parts)


def format_summary(coverage: float, required_coverage: float) -> str:
    lines = []
    if required_coverage != -1:
        lines.append(f"**Required coverage:** {required_coverage:.2%}")
    lines.append(f"**Actual coverage:** {coverage:.2%}")
    if required_coverage != -1:
        status = (
            "PASSED :white_check_mark:"
            if coverage >= required_coverage
            else "FAILED :x:"
        )
        lines.append(f"**Status:** {status}")
    return "\n\n".join(lines)


def create_row(
    key: str,
    group: list[LineCoverage],
    required_coverage: float,
    include_missed_lines: bool,
) -> list[str]:
    missed_lines = [line["line_number"] for line in group if line["hit_count"] == 0]
    total_lines = len(group)
    num_covered = total_lines - len(missed_lines)
    coverage = num_covered / total_lines if total_lines != 0 else 1.0
    row = [
        key,
        get_status_icon(coverage, required_coverage),
        f"{num_covered}/{total_lines}",
        f"{coverage:.2%}" if total_lines != 0 else "--",
    ]
    if include_missed_lines:
        row.append(format_ranges(missed_lines))
    return row


def create_rows(
    key: str,
    lines: list[LineCoverage],
    required_coverage: float,
    include_missed_lines: bool,
    base_coverage: dict[str, float] | None = None,
) -> list[str]:
    rows = []
    for name, group in group_lines(lines, key).items():
        row = create_row(name, group, required_coverage, include_missed_lines)
        if base_coverage is not None:
            row.append(f"{base_coverage[name]:.2%}" if name in base_coverage else "--")
        rows.append("| " + " | ".join(row) + " |")
    return rows


def compute_coverage(lines: list[LineCoverage]) -> float:
    if not lines:
        return 1.0
    covered = sum(1 for line in lines if line["hit_count"] > 0)
    return covered / len(lines)


def create_comment(coverage_json, output_file, head_sha, base_sha, report_url):
    with open(coverage_json) as f:
        data = json.load(f)
    required_coverage = float(data["required_coverage"])
    lines = [parse_line(line) for line in data["lines"]]
    base_lines = data.get("base_lines")
    if not base_lines:
        base_lines = []
    base = [parse_line(line) for line in base_lines]
    base_coverage = {
        name: compute_coverage(group)
        for name, group in group_lines(base, "package").items()
    }
    modified = [line for line in lines if line["was_modified"]]
    mod_summary = format_summary(compute_coverage(modified), required_coverage)
    all_summary = format_summary(compute_coverage(lines), required_coverage)
    mod_rows = create_rows("file_name", modified, required_coverage, True)
    all_rows = create_rows("package", lines, required_coverage, False, base_coverage)
    comment = TEMPLATE.format(
        head_sha=head_sha,
        base_sha=base_sha,
        report_url=report_url,
        mod_summary=mod_summary,
        mod_table="\n".join(mod_rows),
        all_summary=all_summary,
        all_table="\n".join(all_rows),
    )
    with open(output_file, "w") as f:
        f.write(comment)


def main():
    parser = argparse.ArgumentParser(
        description="Read coverage.json and produce a Markdown coverage comment."
    )
    parser.add_argument(
        "--coverage_json",
        required=True,
        help="Path to coverage.json produced by process_coverage.py.",
    )
    parser.add_argument(
        "--output-file",
        required=True,
        help="File into which the generated markdown comment should be written.",
    )
    parser.add_argument(
        "--head-sha",
        required=True,
        help="Git SHA of the head (PR) commit.",
    )
    parser.add_argument(
        "--base-sha",
        required=True,
        help="Git SHA of the base (target) commit.",
    )
    parser.add_argument(
        "--report-url",
        required=True,
        help="Location of the HTML report artifact.",
    )
    args = parser.parse_args()
    create_comment(**vars(args))


if __name__ == "__main__":
    main()
