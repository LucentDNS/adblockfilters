from pathlib import Path


ROOT = Path(__file__).parents[1]
MAINTAINED_DIRECTORIES = (ROOT / "scripts", ROOT / "tests")
MAINTAINED_ROOT_PYTHON_FILES = tuple(ROOT.glob("*.py"))


def test_python_maintenance_files_follow_editorconfig():
    files = sorted(
        {
            *MAINTAINED_ROOT_PYTHON_FILES,
            *(
                path
                for directory in MAINTAINED_DIRECTORIES
                for path in directory.rglob("*.py")
                if path.is_file()
            ),
        }
    )
    assert files, "No maintained Python files were found"

    violations = []
    for path in files:
        content = path.read_bytes()
        relative_path = path.relative_to(ROOT).as_posix()

        if not content.endswith(b"\n"):
            violations.append(f"{relative_path}: missing final newline")
        if b"\r" in content:
            violations.append(f"{relative_path}: CRLF or bare CR line ending")

        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.endswith((b" ", b"\t")):
                violations.append(f"{relative_path}:{line_number}: trailing whitespace")
            if b"\t" in line:
                violations.append(f"{relative_path}:{line_number}: tab indentation")

    assert not violations, "\n".join(violations)


def test_github_workflows_follow_editorconfig():
    workflow_directory = ROOT / ".github" / "workflows"
    files = sorted(workflow_directory.glob("*.yml"))
    assert files, "No GitHub Actions workflow files were found"

    violations = []
    for path in files:
        content = path.read_bytes()
        relative_path = path.relative_to(ROOT).as_posix()

        if not content.endswith(b"\n"):
            violations.append(f"{relative_path}: missing final newline")
        if b"\r" in content:
            violations.append(f"{relative_path}: CRLF or bare CR line ending")

        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.endswith((b" ", b"\t")):
                violations.append(f"{relative_path}:{line_number}: trailing whitespace")
            if b"\t" in line:
                violations.append(f"{relative_path}:{line_number}: tab indentation")

    assert not violations, "\n".join(violations)


def test_maintained_text_files_follow_editorconfig():
    paths = [
        ROOT / "README.md",
        ROOT / "smartdns.conf",
        ROOT / ".editorconfig",
        ROOT / ".gitignore",
        ROOT / "pyproject.toml",
        ROOT / "requirements.txt",
        ROOT / "requirements-dev.txt",
        *sorted((ROOT / "rules").glob("*.txt")),
    ]
    violations = []

    for path in paths:
        content = path.read_bytes()
        relative_path = path.relative_to(ROOT).as_posix()
        if not content.endswith(b"\n"):
            violations.append(f"{relative_path}: missing final newline")
        if b"\r" in content:
            violations.append(f"{relative_path}: CRLF or bare CR line ending")
        for line_number, line in enumerate(content.splitlines(), start=1):
            if line.endswith((b" ", b"\t")):
                violations.append(f"{relative_path}:{line_number}: trailing whitespace")
            if b"\t" in line:
                violations.append(f"{relative_path}:{line_number}: tab character")

    assert not violations, "\n".join(violations)



def test_test_runner_is_a_development_dependency():
    runtime_requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    development_requirements = (
        ROOT / "requirements-dev.txt"
    ).read_text(encoding="utf-8")

    assert "pytest" not in runtime_requirements.lower()
    assert "pytest==9.2.0" in development_requirements
    assert "ruff==0.17.6" in development_requirements


def test_readme_generator_uses_a_real_newline_for_dns_validation_policy():
    source = (ROOT / "readme.py").read_text(encoding="utf-8")

    assert r"均不会作为删除依据。\\n" not in source
    assert r"均不会作为删除依据。\n" in source



def test_git_attributes_enforce_lf_and_preserve_binary_build_outputs():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")

    assert "* text=auto eol=lf" in attributes
    for extension in ("dat", "mrs", "srs", "zip", "gz", "tar"):
        assert f"*.{extension} binary" in attributes
