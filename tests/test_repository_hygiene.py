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
        ROOT / "sources.json",
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


def test_readme_parser_cannot_overwrite_maintained_documentation():
    source = (ROOT / "readme.py").read_text(encoding="utf-8")

    assert "def regenerate(" not in source
    assert "gh-proxy.com" not in source
    assert "ghfast.top" not in source
    assert "ghproxy.net" not in source


def test_git_attributes_enforce_lf_and_preserve_binary_build_outputs():
    attributes = (ROOT / ".gitattributes").read_text(encoding="utf-8")

    assert "* text=auto eol=lf" in attributes
    for extension in ("dat", "mrs", "srs", "zip", "gz", "tar"):
        assert f"*.{extension} binary" in attributes


def test_only_the_two_supported_adguard_product_adapters_are_registered():
    import ast

    app_directory = ROOT / "app"
    expected_modules = {"__init__.py", "base.py", "adguard.py", "adguardhome.py"}
    actual_modules = {path.name for path in app_directory.glob("*.py")}
    assert actual_modules == expected_modules

    filter_tree = ast.parse((ROOT / "filter.py").read_text(encoding="utf-8"))
    registered = []
    for node in ast.walk(filter_tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if not any(isinstance(target, ast.Name) and target.id == "generaterList" for target in targets):
            continue
        assert isinstance(value, ast.List)
        registered = [
            element.func.id
            for element in value.elts
            if isinstance(element, ast.Call) and isinstance(element.func, ast.Name)
        ]
        break

    assert registered == ["AdGuard", "AdGuardHome"]
