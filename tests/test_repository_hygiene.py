from pathlib import Path


ROOT = Path(__file__).parents[1]
MAINTAINED_DIRECTORIES = (ROOT / "scripts", ROOT / "tests")


def test_python_maintenance_files_follow_editorconfig():
    files = sorted(
        path
        for directory in MAINTAINED_DIRECTORIES
        for path in directory.rglob("*.py")
        if path.is_file()
    )
    assert files, "No maintained Python files were found"

    violations = []
    for path in files:
        content = path.read_bytes()
        relative_path = path.relative_to(ROOT).as_posix()

        if not content.endswith(b"\\n"):
            violations.append(f"{relative_path}: missing final newline")
        if b"\\r" in content:
            violations.append(f"{relative_path}: CRLF or bare CR line ending")

        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.endswith((b" ", b"\\t")):
                violations.append(f"{relative_path}:{line_number}: trailing whitespace")
            if b"\\t" in line:
                violations.append(f"{relative_path}:{line_number}: tab indentation")

    assert not violations, "\\n".join(violations)
