#!/usr/bin/env python3
"""
Comprehensive test runner script for the cryptography messenger application.
Runs all test suites including functionality, security, performance, and analysis tests.
"""

import sys
import subprocess
import time
from pathlib import Path


def run_command(cmd, description, timeout=300):
    """Run a command and return success status."""
    print(f"\n{'=' * 60}")
    print(f"Running: {description}")
    print(f"Command: {' '.join(cmd)}")
    print(f"{'=' * 60}")

    try:
        start_time = time.time()
        result = subprocess.run(
            cmd, capture_output=False, timeout=timeout, cwd=Path(__file__).parent
        )
        end_time = time.time()

        duration = end_time - start_time

        if result.returncode == 0:
            print(f"\n{description} PASSED (took {duration:.2f}s)")
            return True
        else:
            print(f"\n{description} FAILED (took {duration:.2f}s)")
            return False

    except subprocess.TimeoutExpired:
        print(f"\n{description} TIMED OUT")
        return False
    except Exception as e:
        print(f"\n{description} ERROR: {e}")
        return False


def main():
    """Run all test suites."""
    print("🧪 Cryptography Messenger - Comprehensive Test Suite")
    print("=" * 60)

    # Get python executable path
    try:
        result = subprocess.run(
            [sys.executable, "-c", "import sys; print(sys.executable)"],
            capture_output=True,
            text=True,
        )
        python_exe = result.stdout.strip()
        print(f"Using Python: {python_exe}")
    except:
        python_exe = sys.executable

    results = []

    # 1. Basic functionality tests
    results.append(
        run_command(
            [python_exe, "-m", "pytest", "test_messenger.py", "-v", "--tb=short"],
            "Core Functionality Tests",
        )
    )

    # 2. Security vulnerability tests
    results.append(
        run_command(
            [python_exe, "-m", "pytest", "test_security.py", "-v", "--tb=short"],
            "Security Vulnerability Tests",
        )
    )

    # 3. Performance tests
    results.append(
        run_command(
            [
                python_exe,
                "-m",
                "pytest",
                "test_performance.py",
                "-v",
                "--tb=short",
                "-m",
                "not slow",
            ],
            "Performance Tests (Quick)",
        )
    )

    # 4. Security analysis tests
    results.append(
        run_command(
            [
                python_exe,
                "-m",
                "pytest",
                "test_security_analysis.py",
                "-v",
                "--tb=short",
            ],
            "Security Analysis Tests",
        )
    )

    # 5. Code coverage report
    results.append(
        run_command(
            [
                python_exe,
                "-m",
                "pytest",
                "--cov=messenger",
                "--cov-report=html",
                "--cov-report=term",
            ],
            "Code Coverage Analysis",
        )
    )

    # 6. Run bandit security scanner directly
    try:
        results.append(
            run_command(
                ["bandit", "-r", "messenger.py", "-v"],
                "Bandit Security Scanner",
                timeout=60,
            )
        )
    except FileNotFoundError:
        print("\nBandit not available - skipping direct scan")
        results.append(True)  # Don't fail overall if bandit is not installed

    # 7. Run safety vulnerability check directly
    try:
        results.append(
            run_command(["safety", "check"], "Safety Vulnerability Scanner", timeout=60)
        )
    except FileNotFoundError:
        print("\nSafety not available - skipping direct scan")
        results.append(True)  # Don't fail overall if safety is not installed

    # 8. Property-based testing with Hypothesis
    results.append(
        run_command(
            [
                python_exe,
                "-m",
                "pytest",
                "test_messenger.py::TestPropertyBasedTesting",
                "-v",
            ],
            "Property-Based Testing",
        )
    )

    # 9. Integration tests
    results.append(
        run_command(
            [
                python_exe,
                "-m",
                "pytest",
                "test_messenger.py::test_integration_full_protocol",
                "-v",
            ],
            "Integration Tests",
        )
    )

    # Summary
    print(f"\n{'=' * 60}")
    print("TEST SUMMARY")
    print(f"{'=' * 60}")

    test_names = [
        "Core Functionality Tests",
        "Security Vulnerability Tests",
        "Performance Tests",
        "Security Analysis Tests",
        "Code Coverage Analysis",
        "Bandit Security Scanner",
        "Safety Vulnerability Scanner",
        "Property-Based Testing",
        "Integration Tests",
    ]

    passed = sum(results)
    total = len(results)

    for i, (name, result) in enumerate(zip(test_names, results)):
        status = "PASS" if result else "FAIL"
        print(f"{i + 1:2d}. {name:<35} {status}")

    print(f"\nOverall Result: {passed}/{total} test suites passed")

    if passed == total:
        print("ALL TESTS PASSED!")
        return 0
    else:
        print(f"{total - passed} test suite(s) failed!")
        return 1


if __name__ == "__main__":
    sys.exit(main())
