
from backend.scanner.detector import detect_framework


TEST_PROJECTS = {
    "tests": [
        "Java (framework not identified)",
        "FastAPI",
        "Express.js",
        ".NET",
    ],
    "tests/python_test": [
        "FastAPI",
    ],
    "tests/node_test": [
        "Express.js",
    ],
    "tests/dotnet_test": [
        ".NET",
    ],
}


def main():
    print("=" * 50)
    print("FRAMEWORK DETECTION TESTS")
    print("=" * 50)

    passed = 0
    failed = 0

    for project_path, expected_frameworks in TEST_PROJECTS.items():
        try:
            detected = detect_framework(project_path)

            expected = set(expected_frameworks)
            actual = set(
                framework.strip()
                for framework in detected.split(",")
            )

            success = actual == expected

            print(f"\nProject: {project_path}")
            print(f"Expected: {', '.join(expected_frameworks)}")
            print(f"Detected: {detected}")

            if success:
                print("Result: PASS")
                passed += 1
            else:
                print("Result: FAIL")
                failed += 1

        except (OSError, ValueError) as error:
            print(f"\nProject: {project_path}")
            print(f"Result: FAIL - {error}")
            failed += 1

    print("\n" + "=" * 50)
    print(f"Tests passed: {passed}")
    print(f"Tests failed: {failed}")
    print("=" * 50)

    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
