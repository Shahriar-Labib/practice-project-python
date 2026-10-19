
import json
from pathlib import Path


IGNORED_DIRECTORIES = {
    ".git",
    ".idea",
    ".venv",
    "venv",
    "__pycache__",
    "node_modules",
    "target",
    "build",
    "dist",
    "bin",
    "obj",
}


def get_project_files(project):
    """Find project files without scanning generated directories."""

    for path in project.rglob("*"):
        if not path.is_file():
            continue

        relative_parts = path.relative_to(project).parts

        if any(
            part.lower() in IGNORED_DIRECTORIES
            for part in relative_parts[:-1]
        ):
            continue

        yield path


def detect_framework(project_path):
    """
    Detect all supported frameworks and languages in a project.

    Returns a comma-separated string to preserve compatibility
    with the existing scanner and report generator.
    """

    project = Path(project_path).resolve()

    if not project.exists() or not project.is_dir():
        raise ValueError(
            f"Project directory does not exist: {project}"
        )

    files = list(get_project_files(project))
    filenames = {path.name.lower() for path in files}
    suffixes = {path.suffix.lower() for path in files}

    detected = []

    # Java / Spring Boot
    java_configs = {
        "pom.xml",
        "build.gradle",
        "build.gradle.kts",
    }

    spring_boot = False

    for path in files:
        if path.name.lower() not in java_configs:
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace"
            ).lower()

            if (
                "spring-boot" in content
                or "org.springframework.boot" in content
            ):
                spring_boot = True
                break
        except OSError:
            continue

    if spring_boot:
        detected.append("Spring Boot")
    elif ".java" in suffixes:
        detected.append("Java (framework not identified)")

    # Python / FastAPI
    python_config_names = {
        "requirements.txt",
        "pyproject.toml",
    }

    fastapi = False

    for path in files:
        if path.name.lower() not in python_config_names:
            continue

        try:
            content = path.read_text(
                encoding="utf-8",
                errors="replace"
            ).lower()

            if "fastapi" in content:
                fastapi = True
                break
        except OSError:
            continue

    if fastapi:
        detected.append("FastAPI")
    elif ".py" in suffixes:
        detected.append("Python (framework not identified)")

    # Node.js / Express
    package_files = [
        path for path in files
        if path.name.lower() == "package.json"
    ]

    express = False
    node_project = False

    for path in package_files:
        node_project = True

        try:
            package_data = json.loads(
                path.read_text(
                    encoding="utf-8",
                    errors="replace"
                )
            )

            if not isinstance(package_data, dict):
                continue

            dependencies = {}

            for section in ("dependencies", "devDependencies"):
                section_data = package_data.get(section, {})

                if isinstance(section_data, dict):
                    dependencies.update(section_data)

            if "express" in dependencies:
                express = True
                break

        except (OSError, json.JSONDecodeError):
            continue

    if express:
        detected.append("Express.js")
    elif node_project or ".js" in suffixes or ".mjs" in suffixes:
        detected.append("Node.js (framework not identified)")

    # C# / .NET
    dotnet_project = any(
        path.suffix.lower() in {".csproj", ".sln"}
        for path in files
    )

    if dotnet_project:
        detected.append(".NET")
    elif ".cs" in suffixes:
        detected.append("C# (project type not identified)")

    if not detected:
        return "Unknown"

    return ", ".join(detected)
