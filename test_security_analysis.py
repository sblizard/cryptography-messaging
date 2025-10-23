"""
Security analysis and vulnerability scanner tests.
Uses bandit and other security tools to detect vulnerabilities.
"""

import pytest
import subprocess
from pathlib import Path


class TestSecurityAnalysis:
    """Test using security analysis tools."""

    def test_bandit_security_scan(self):
        """Run bandit security scanner on the codebase."""
        # Get the project directory
        project_dir = Path(__file__).parent

        # Run bandit on the messenger module
        try:
            result = subprocess.run(
                ["bandit", "-r", str(project_dir / "messenger.py"), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                # Bandit found security issues
                print("Bandit output:")
                print(result.stdout)
                print(result.stderr)

                # Parse JSON output to get issue count
                import json

                try:
                    bandit_results = json.loads(result.stdout)
                    issues = bandit_results.get("results", [])

                    # Categorize issues by severity
                    high_issues = [
                        i for i in issues if i.get("issue_severity") == "HIGH"
                    ]
                    medium_issues = [
                        i for i in issues if i.get("issue_severity") == "MEDIUM"
                    ]
                    low_issues = [i for i in issues if i.get("issue_severity") == "LOW"]

                    print("Security issues found:")
                    print(f"  High: {len(high_issues)}")
                    print(f"  Medium: {len(medium_issues)}")
                    print(f"  Low: {len(low_issues)}")

                    # Fail test if high severity issues found
                    if high_issues:
                        pytest.fail(
                            f"High severity security issues found: {len(high_issues)}"
                        )

                    # Warn about medium severity issues
                    if medium_issues:
                        print(
                            f"Warning: {len(medium_issues)} medium severity issues found"
                        )

                except json.JSONDecodeError:
                    print("Could not parse bandit JSON output")
            else:
                print("Bandit scan completed with no security issues found")

        except subprocess.TimeoutExpired:
            pytest.skip("Bandit scan timed out")
        except FileNotFoundError:
            pytest.skip("Bandit not installed")

    def test_safety_vulnerability_check(self):
        """Check for known vulnerabilities in dependencies using safety."""
        try:
            result = subprocess.run(
                ["safety", "check", "--json"],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print("Safety output:")
                print(result.stdout)
                print(result.stderr)

                # Parse JSON output
                import json

                try:
                    safety_results = json.loads(result.stdout)
                    vulnerabilities = (
                        safety_results if isinstance(safety_results, list) else []
                    )

                    if vulnerabilities:
                        print(
                            f"Found {len(vulnerabilities)} known vulnerabilities in dependencies:"
                        )
                        for vuln in vulnerabilities:
                            print(
                                f"  - {vuln.get('package', 'unknown')}: {vuln.get('advisory', 'no description')}"
                            )

                        pytest.fail(
                            f"Known vulnerabilities found in dependencies: {len(vulnerabilities)}"
                        )

                except json.JSONDecodeError:
                    # Safety might not return JSON on error
                    if "No known security vulnerabilities found" not in result.stdout:
                        pytest.fail("Safety check failed with errors")
            else:
                print("Safety scan completed - no known vulnerabilities found")

        except subprocess.TimeoutExpired:
            pytest.skip("Safety scan timed out")
        except FileNotFoundError:
            pytest.skip("Safety not installed")

    def test_pickle_usage_analysis(self):
        """Analyze usage of pickle module for security risks."""
        # Read the messenger.py file
        messenger_file = Path(__file__).parent / "messenger.py"

        if not messenger_file.exists():
            pytest.skip("messenger.py not found")

        content = messenger_file.read_text()

        # Check for pickle usage
        pickle_imports = []
        pickle_calls = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if "import pickle" in line or "from pickle import" in line:
                pickle_imports.append((i, line.strip()))

            if "pickle.load" in line or "pickle.loads" in line:
                pickle_calls.append((i, line.strip()))

        if pickle_imports:
            print(f"Found pickle imports: {len(pickle_imports)}")
            for line_num, line in pickle_imports:
                print(f"  Line {line_num}: {line}")

        if pickle_calls:
            print(f"Found pickle deserialization calls: {len(pickle_calls)}")
            for line_num, line in pickle_calls:
                print(f"  Line {line_num}: {line}")

            # Warn about pickle deserialization risks
            print("WARNING: pickle.loads() can execute arbitrary code.")
            print("Ensure all pickle data comes from trusted sources.")

    def test_random_number_generation_analysis(self):
        """Analyze random number generation for security."""
        messenger_file = Path(__file__).parent / "messenger.py"

        if not messenger_file.exists():
            pytest.skip("messenger.py not found")

        content = messenger_file.read_text()

        # Check for proper random number generation
        secure_random = []
        insecure_random = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            if "os.urandom" in line:
                secure_random.append((i, line.strip()))

            if "random." in line and "import random" in content:
                insecure_random.append((i, line.strip()))

        print(f"Secure random usage (os.urandom): {len(secure_random)}")
        print(f"Potentially insecure random usage: {len(insecure_random)}")

        if insecure_random:
            print("WARNING: Found usage of potentially insecure random module:")
            for line_num, line in insecure_random:
                print(f"  Line {line_num}: {line}")
            print(
                "Consider using os.urandom() or secrets module for cryptographic purposes."
            )

    def test_hardcoded_secrets_detection(self):
        """Check for hardcoded secrets or keys."""
        messenger_file = Path(__file__).parent / "messenger.py"

        if not messenger_file.exists():
            pytest.skip("messenger.py not found")

        content = messenger_file.read_text()

        # Patterns that might indicate hardcoded secrets
        suspicious_patterns = [
            (r'["\']([A-Za-z0-9+/]{32,}={0,2})["\']', "Base64-like string"),
            (r'["\']([0-9a-fA-F]{32,})["\']', "Hex string"),
            (r'password\s*=\s*["\']([^"\']+)["\']', "Hardcoded password"),
            (r'key\s*=\s*["\']([^"\']+)["\']', "Hardcoded key"),
            (r'secret\s*=\s*["\']([^"\']+)["\']', "Hardcoded secret"),
        ]

        import re

        findings = []
        lines = content.split("\n")

        for i, line in enumerate(lines, 1):
            for pattern, description in suspicious_patterns:
                matches = re.finditer(pattern, line, re.IGNORECASE)
                for match in matches:
                    # Skip obvious test data or common strings
                    matched_text = match.group(1)
                    if len(matched_text) > 16 and not any(
                        test_word in matched_text.lower()
                        for test_word in ["test", "example", "demo", "utf-8"]
                    ):
                        findings.append((i, description, matched_text[:20] + "..."))

        if findings:
            print("Potential hardcoded secrets found:")
            for line_num, desc, text in findings:
                print(f"  Line {line_num}: {desc} - {text}")
            print("Review these findings to ensure no actual secrets are hardcoded.")

    def test_cryptographic_constants_analysis(self):
        """Analyze cryptographic constants and algorithms used."""
        messenger_file = Path(__file__).parent / "messenger.py"

        if not messenger_file.exists():
            pytest.skip("messenger.py not found")

        content = messenger_file.read_text()

        # Check for cryptographic algorithm usage
        crypto_usage = {
            "Hash algorithms": [],
            "Encryption algorithms": [],
            "Key derivation": [],
            "Signature algorithms": [],
            "Curves": [],
        }

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            # Hash algorithms
            if "SHA256" in line:
                crypto_usage["Hash algorithms"].append((i, "SHA256"))
            if "SHA1" in line:
                crypto_usage["Hash algorithms"].append((i, "SHA1 (WEAK)"))
            if "MD5" in line:
                crypto_usage["Hash algorithms"].append((i, "MD5 (WEAK)"))

            # Encryption
            if "AES" in line:
                crypto_usage["Encryption algorithms"].append((i, "AES"))
            if "DES" in line and "AES" not in line:
                crypto_usage["Encryption algorithms"].append((i, "DES (WEAK)"))

            # Key derivation
            if "HKDF" in line:
                crypto_usage["Key derivation"].append((i, "HKDF"))
            if "PBKDF2" in line:
                crypto_usage["Key derivation"].append((i, "PBKDF2"))

            # Signatures
            if "ECDSA" in line:
                crypto_usage["Signature algorithms"].append((i, "ECDSA"))
            if "RSA" in line:
                crypto_usage["Signature algorithms"].append((i, "RSA"))

            # Curves
            if "SECP256R1" in line:
                crypto_usage["Curves"].append((i, "SECP256R1 (P-256)"))
            if "SECP256K1" in line:
                crypto_usage["Curves"].append((i, "SECP256K1"))

        print("Cryptographic algorithm analysis:")
        for category, findings in crypto_usage.items():
            if findings:
                print(f"\n{category}:")
                for line_num, algo in findings:
                    print(f"  Line {line_num}: {algo}")

        # Check for weak algorithms
        weak_algos = []
        for category, findings in crypto_usage.items():
            for line_num, algo in findings:
                if "WEAK" in algo:
                    weak_algos.append((line_num, algo))

        if weak_algos:
            print(f"\nWARNING: Found {len(weak_algos)} weak cryptographic algorithms:")
            for line_num, algo in weak_algos:
                print(f"  Line {line_num}: {algo}")

    def test_exception_handling_security(self):
        """Analyze exception handling for information disclosure."""
        messenger_file = Path(__file__).parent / "messenger.py"

        if not messenger_file.exists():
            pytest.skip("messenger.py not found")

        content = messenger_file.read_text()

        # Look for broad exception handling that might hide security issues
        broad_exceptions = []
        exception_reraises = []

        lines = content.split("\n")
        for i, line in enumerate(lines, 1):
            stripped = line.strip()

            # Broad exception handling
            if "except:" in stripped or "except Exception:" in stripped:
                broad_exceptions.append((i, stripped))

            # Exception re-raising
            if stripped == "raise" or "raise Exception" in stripped:
                exception_reraises.append((i, stripped))

        if broad_exceptions:
            print(f"Found {len(broad_exceptions)} broad exception handlers:")
            for line_num, line in broad_exceptions:
                print(f"  Line {line_num}: {line}")
            print(
                "Consider using specific exception types to avoid masking security issues."
            )

        if exception_reraises:
            print(f"Found {len(exception_reraises)} exception re-raises:")
            for line_num, line in exception_reraises:
                print(f"  Line {line_num}: {line}")


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
