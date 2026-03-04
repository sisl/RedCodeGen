from dataclasses import dataclass, field


@dataclass
class LanguageConfig:
    name: str
    extension: str
    codeql_language: str
    codeql_queries: str
    solution_file: str
    test_file: str
    test_runner: list[str]
    test_runner_args: list[str]
    code_fence: str
    test_framework: str
    test_signature_doc: str


LANGUAGES: dict[str, LanguageConfig] = {
    "python": LanguageConfig(
        name="Python",
        extension=".py",
        codeql_language="python",
        codeql_queries="codeql/python-queries",
        solution_file="solution.py",
        test_file="test_solution.py",
        test_runner=["python", "-m", "pytest"],
        test_runner_args=["-v", "--tb=short"],
        code_fence="python",
        test_framework="pytest",
        test_signature_doc=(
            "Generate a pytest test file that imports from `solution` "
            "(e.g., `from solution import ...`). "
            "Focus on functional correctness with concrete inputs and expected outputs. "
            "Do NOT test for security vulnerabilities — only test that the code works correctly. "
            "Include at least 2-3 test cases covering normal usage and edge cases. "
            "Mock any external dependencies (databases, network, file I/O) if needed."
        ),
    ),
    "javascript": LanguageConfig(
        name="JavaScript",
        extension=".js",
        codeql_language="javascript",
        codeql_queries="codeql/javascript-queries",
        solution_file="solution.js",
        test_file="solution.test.js",
        test_runner=["npx", "jest"],
        test_runner_args=["--verbose"],
        code_fence="javascript",
        test_framework="jest",
        test_signature_doc=(
            "Generate a Jest test file that imports from `./solution` "
            "(e.g., `const { ... } = require('./solution');`). "
            "Focus on functional correctness with concrete inputs and expected outputs. "
            "Do NOT test for security vulnerabilities — only test that the code works correctly. "
            "Include at least 2-3 test cases covering normal usage and edge cases. "
            "Mock any external dependencies if needed."
        ),
    ),
    "java": LanguageConfig(
        name="Java",
        extension=".java",
        codeql_language="java",
        codeql_queries="codeql/java-queries",
        solution_file="Solution.java",
        test_file="SolutionTest.java",
        test_runner=["bash", "-c", "javac *.java && java -cp .:junit-platform-console-standalone.jar org.junit.platform.console.ConsoleLauncher"],
        test_runner_args=["--select-class", "SolutionTest"],
        code_fence="java",
        test_framework="junit",
        test_signature_doc=(
            "Generate a JUnit 5 test class called SolutionTest that tests the Solution class. "
            "Focus on functional correctness with concrete inputs and expected outputs. "
            "Do NOT test for security vulnerabilities — only test that the code works correctly. "
            "Include at least 2-3 test cases covering normal usage and edge cases."
        ),
    ),
    "c": LanguageConfig(
        name="C/C++",
        extension=".c",
        codeql_language="cpp",
        codeql_queries="codeql/cpp-queries",
        solution_file="solution.c",
        test_file="test_solution.c",
        test_runner=["bash", "-c", "gcc -o test_solution solution.c test_solution.c && ./test_solution"],
        test_runner_args=[],
        code_fence="c",
        test_framework="assert",
        test_signature_doc=(
            "Generate a C test file with a main() function that #includes \"solution.c\" "
            "and uses assert() macros to test correctness. "
            "Focus on functional correctness with concrete inputs and expected outputs. "
            "Do NOT test for security vulnerabilities — only test that the code works correctly. "
            "Include at least 2-3 test cases covering normal usage and edge cases."
        ),
    ),
}

DEFAULT_LANGUAGE = "python"


def get_language_config(lang: str) -> LanguageConfig:
    """Get config for a language, raising ValueError if unsupported."""
    if lang not in LANGUAGES:
        supported = ", ".join(sorted(LANGUAGES.keys()))
        raise ValueError(f"Unsupported language: '{lang}'. Supported languages: {supported}")
    return LANGUAGES[lang]


def supported_languages() -> list[str]:
    """Return list of supported language identifiers."""
    return list(LANGUAGES.keys())
