import argparse
import json
import os
import xml.etree.ElementTree as ET

def collect_line_coverage(cobertura_file, changed_lines_file=None):
    changed_lines = {}
    if changed_lines_file:
        with open(changed_lines_file) as f:
            changed_lines = json.load(f)
    tree = ET.parse(cobertura_file)
    root = tree.getroot()
    for clazz in root.findall("packages/package/classes/class"):
        file_name = clazz.attrib["filename"]
        package = file_name.split("/")[0]
        for line in clazz.findall("lines/line"):
            line_number = int(line.attrib["number"])
            was_modified = line_number in changed_lines.get(file_name, [])
            yield dict(
                package=package,
                file_name=file_name,
                line_number=line_number,
                hit_count=int(line.attrib["hits"]),
                was_modified=was_modified,
            )


def check_criteria(lines, required_coverage):
    if required_coverage == -1 or len(lines) == 0:
        return True
    covered = sum(1 for line in lines if line["hit_count"] > 0)
    return (covered / len(lines)) >= required_coverage


def process(
    cobertura_file,
    base_cobertura_file,
    changed_lines_file,
    required_coverage,
    output_dir,
):
    lines = list(collect_line_coverage(cobertura_file, changed_lines_file))
    base_lines = None
    if base_cobertura_file and os.path.isfile(base_cobertura_file):
        base_lines = list(collect_line_coverage(base_cobertura_file))
    modified_lines = [line for line in lines if line["was_modified"]]
    passed = check_criteria(lines, required_coverage) and \
        check_criteria(modified_lines, required_coverage)
    os.makedirs(output_dir, exist_ok=True)
    with open(os.path.join(output_dir, "status.txt"), "w") as f:
        f.write("PASSED" if passed else "FAILED")
    with open(os.path.join(output_dir, "coverage.json"), "w") as f:
        data = dict(lines=lines, required_coverage=required_coverage, base_lines=base_lines)
        json.dump(data, f, indent=2)


def main():
    parser = argparse.ArgumentParser(
        description="Process a Cobertura coverage report and produce coverage data."
    )
    parser.add_argument(
        "--cobertura-file",
        required=True,
        help="Path to the Cobertura XML coverage report for the head commit.",
    )
    parser.add_argument(
        "--base-cobertura-file",
        default=None,
        help="Path to the Cobertura XML coverage report for the base commit.",
    )
    parser.add_argument(
        "--changed-lines-file",
        required=True,
        help="Path to a JSON file mapping filenames to lists of changed line numbers.",
    )
    parser.add_argument(
        "--required-coverage",
        type=float,
        default=-1,
        help="Minimum coverage ratio (0.0-1.0) to pass. Use -1 to disable the check (default: -1).",
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write status.txt and coverage.json.",
    )
    args = parser.parse_args()
    process(**vars(args))


if __name__ == "__main__":
    main()
