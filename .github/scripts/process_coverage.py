import json
import os
import itertools
import pathlib
import sys
import xml.etree.ElementTree as ET

TEMPLATE = """
# Coverage Report
Head Commit: $$HEAD_SHA$$

Base Commit: $$BASE_SHA$$

[Download the full coverage report.]($$REPORT_LOCATION$$)

## Coverage of Added or Modified Lines of Rust Code
$$MOD_SUMMARY$$

<details>
<summary><b>Details</b></summary>

| File | Status | Covered | Coverage | Missed Lines |
|:-----|:------:|:-------:|---------:|:-------------|
$$MOD_TABLE$$
</details>

## Coverage of All Lines of Rust Code
$$ALL_SUMMARY$$

<details>
<summary><b>Details</b></summary>

| Package | Status | Covered | Coverage | Base Coverage |
|:--------|:------:|:-------:|---------:|--------------:|
$$ALL_TABLE$$
</details>
"""


def to_ranges(iterable):
    iterable = sorted(set(iterable))
    # Group elements by the difference between the value and its index
    for _, group in itertools.groupby(enumerate(iterable), lambda t: t[1] - t[0]):
        group = list(group)
        # Take the value of the first and last elements of the group
        yield group[0][1], group[-1][1]


def format_lines(lines):
    x = [str(x) if x == y else f"{x}-{y}" for x, y in to_ranges(lines)]
    return ", ".join(x)


def collect_line_coverage(cobertura_file):
    tree = ET.parse(cobertura_file)
    root = tree.getroot()
    for clazz in root.findall("packages/package/classes/class"):
        file_name = clazz.attrib["filename"]
        package = file_name.split(os.path.sep)[0]
        for line in clazz.findall("lines/line"):
            yield dict(
                package=package,
                file_name=file_name,
                line_number=int(line.attrib["number"]),
                hit_count=int(line.attrib["hits"]),
            )


def create_comment(template_variables):
    result = TEMPLATE
    for k, v in template_variables.items():
        result = result.replace(f"$${k.upper()}$$", v)
    return result


def write_results(output_dir, passed, comment):
    os.makedirs(pathlib.Path(output_dir), exist_ok=True)
    status_file = os.path.join(output_dir, "status.txt")
    with open(status_file, "w") as f:
        f.write("PASSED" if passed else "FAILED")
    comment_file = os.path.join(output_dir, "markdown.md")
    with open(comment_file, "w") as f:
        f.write(comment)


def read_json(file):
    with open(file) as f:
        return json.load(f)


def was_modified(entry, changed_lines):
    file_name = entry["file_name"]
    return (
        file_name in changed_lines and entry["line_number"] in changed_lines[file_name]
    )


def santize_name(name):
    allowed = ["-", "_", os.path.sep, "/", "."]
    return "".join(filter(lambda c: str.isalnum(c) or c in allowed, name))


def get_status(actual_coverage, required_coverage):
    if required_coverage == -1:
        return ":white_circle:"
    elif actual_coverage >= required_coverage:
        return ":green_circle:"
    elif actual_coverage >= (required_coverage - 0.1):
        return ":yellow_circle:"
    else:
        return ":red_circle:"


def create_table(entries, required_coverage, list_missed, group_key):
    entries = sorted(entries, key=lambda e: e[group_key])
    groups = itertools.groupby(entries, lambda e: e[group_key])
    for name, group in groups:
        group = list(group)
        missed_lines = [x["line_number"] for x in group if x["hit_count"] == 0]
        total_lines = len(group)
        if total_lines != 0:
            num_covered = total_lines - len(missed_lines)
            coverage = num_covered / total_lines
            values = [
                santize_name(name),
                f"{coverage:.2%}",
                f"{num_covered}/{total_lines}",
                get_status(coverage, required_coverage),
            ]
            if list_missed:
                values.append(format_lines(missed_lines))
            yield " | ".join(values)


def compute_actual_coverage(entries):
    total = len(entries)
    covered = len([x for x in entries if x["hit_count"] != 0])
    return covered / total if total != 0 else 1.0


def group_entries(entries, key):
    entries = sorted(entries, key=lambda e: e[key])
    groups = itertools.groupby(entries, lambda e: e[key])
    result = {}
    for name, group in groups:
        group = list(group)
        if len(group) != 0:
            result[name] = group
    return result


def create_row(name, group, required_coverage):
    missed_lines = [x["line_number"] for x in group if x["hit_count"] == 0]
    total_lines = len(group)
    num_covered = total_lines - len(missed_lines)
    coverage = num_covered / total_lines if total_lines != 0 else 1.0
    return [
        santize_name(name),
        get_status(coverage, required_coverage),
        f"{num_covered}/{total_lines}",
        f"{coverage:.2%}" if total_lines != 0 else "--",
        format_lines(missed_lines),
    ]


def create_comparison_table(entries, base_entries, required_coverage):
    group_key = "package"
    base_groups = group_entries(base_entries, group_key)
    groups = group_entries(entries, group_key)
    for name, group in groups.items():
        row = create_row(name, list(group), required_coverage)[:-1]
        if name in base_groups:
            base_coverage = compute_actual_coverage(base_groups[name])
            row.append(f"{base_coverage:.2%}")
        else:
            row.append("--")
        yield row
    for name, base_group in base_groups:
        if name in groups:
            continue
        row = create_row(name, list(group), required_coverage)[:-1]
        base_coverage = compute_actual_coverage(base_group)
        row.append(f"{base_coverage:.2%}")
        yield row


def format_table(rows):
    return "\n".join([" | ".join(row) for row in rows])


def create_summary(entries, required_coverage):
    actual_coverage = 1.0 if len(entries) == 0 else compute_actual_coverage(entries)
    if required_coverage == -1:
        return f"**Overall coverage:** {actual_coverage:.2%}"
    passed = actual_coverage >= required_coverage
    return (
        f"**Required coverage:** {required_coverage:.2%}"
        + "\n\n"
        + f"**Actual coverage:** {actual_coverage:.2%}"
        + "\n\n"
        + f"**Status:** {"PASSED" if passed else "FAILED"} {":white_check_mark:" if passed else ":x:"}"
    )


def check_criteria(entries, required_coverage):
    return (
        required_coverage == -1
        or len(entries) == 0
        or (compute_actual_coverage(entries) >= required_coverage)
    )


def process(
    cobertura_file,
    changed_lines_file,
    required_coverage,
    head_sha,
    base_sha,
    report_location,
    base_cobertura_file,
    output_dir,
):
    required_coverage = float(required_coverage)
    entries = list(collect_line_coverage(cobertura_file))
    changed_lines = read_json(changed_lines_file)
    # Remove lines that were not modified
    modified_entries = list(filter(lambda e: was_modified(e, changed_lines), entries))
    # Read coverage for PR BASE
    base_entries = []
    if os.path.exists(base_cobertura_file):
        base_entries = list(collect_line_coverage(base_cobertura_file))
    # Create tables
    all_table = create_comparison_table(entries, base_entries, required_coverage)
    mod_table = [
        create_row(name, list(group), required_coverage)
        for name, group in group_entries(modified_entries, "file_name").items()
    ]
    template_variables = dict(
        REPORT_LOCATION=report_location,
        HEAD_SHA=head_sha,
        BASE_SHA=base_sha,
        ALL_SUMMARY=create_summary(entries, required_coverage),
        MOD_SUMMARY=create_summary(modified_entries, required_coverage),
        ALL_TABLE=format_table(all_table),
        MOD_TABLE=format_table(mod_table),
    )
    passed = check_criteria(entries, required_coverage)
    passed &= check_criteria(modified_entries, required_coverage)
    write_results(
        output_dir,
        passed,
        create_comment(template_variables),
    )


def main():
    process(*sys.argv[1:])


if __name__ == "__main__":
    main()
