"""Classical checker for hardcoded secrets using detect-secrets and gitleaks."""

import re
import subprocess
import tempfile
import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence


class HardcodedSecretsChecker(BaseChecker):
    """Checker for hardcoded secrets using detect-secrets and gitleaks."""

    def __init__(self):
        super().__init__(
            name="hardcoded_secrets",
            description="Detects hardcoded secrets like API keys, passwords, and tokens",
            is_classical=True
        )

        # Common patterns for secrets that might not be caught by detect-secrets/gitleaks
        self.secret_patterns = {
            "api_key_pattern": re.compile(
                r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
            ),
            "password_pattern": re.compile(
                r'(?i)(password|passwd|pwd)\s*[=:]\s*["\']([^"\']{8,})["\']'
            ),
            "token_pattern": re.compile(
                r'(?i)(token|bearer)\s*[=:]\s*["\']([a-zA-Z0-9_-]{20,})["\']'
            ),
            "secret_pattern": re.compile(
                r'(?i)(secret|key)\s*[=:]\s*["\']([a-zA-Z0-9_-]{16,})["\']'
            ),
        }

    def _get_supported_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return ['.py', '.js', '.ts', '.json', '.yaml', '.yml', '.env', '.config', '.ini', '.cfg']

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Check a file for hardcoded secrets."""
        findings = []

        # Use detect-secrets if available
        # TODO: Fix detect-secrets integration - currently has plugin loading issues
        # detect_secrets_findings = self._check_with_detect_secrets(file_path, content)
        # findings.extend(detect_secrets_findings)

        # Use gitleaks if available
        gitleaks_findings = self._check_with_gitleaks(file_path, content)
        findings.extend(gitleaks_findings)

        # Use regex patterns as primary detection method
        regex_findings = self._check_with_regex(file_path, content)
        findings.extend(regex_findings)

        return findings

    def _check_with_detect_secrets(self, file_path: Path, content: str) -> List[Finding]:
        """Check file using detect-secrets Python API."""
        findings = []

        try:
            from detect_secrets import SecretsCollection
            from detect_secrets.core import scan

            # Write content to temporary file for detect-secrets
            with tempfile.NamedTemporaryFile(mode='w', suffix=file_path.suffix, delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                # Use detect-secrets Python API directly
                secrets = scan.scan_file(temp_file_path)

                # Process findings
                for secret in secrets:
                    line_number = secret.line_number
                    secret_type = secret.type

                    findings.append(Finding(
                        id=f"detect_secrets_{file_path.name}_{line_number}_{secret_type}",
                        title="Hardcoded Secret Detected (detect-secrets)",
                        description=f"Potential hardcoded {secret_type} found",
                        severity=Severity.CRITICAL,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(
                            file=file_path,
                            line_start=line_number,
                            line_end=line_number
                        ),
                        checker_name=self.name,
                        evidence=[Evidence(
                            type="detect-secrets",
                            description=f"detect-secrets detected {secret_type}",
                            confidence=0.9,
                            details={"type": secret_type, "line": line_number}
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description="Move secret to environment variables or secure configuration",
                            prompt="Replace hardcoded secret with environment variable reference"
                        )]
                    ))

            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)

        except ImportError:
            # detect-secrets not available
            pass
        except Exception:
            # Any other error with detect-secrets
            pass

        return findings

    def _check_with_gitleaks(self, file_path: Path, content: str) -> List[Finding]:
        """Check file using gitleaks (system binary)."""
        findings = []

        try:
            # Check if gitleaks is available
            subprocess.run(['gitleaks', '--version'], capture_output=True, check=True)
        except (FileNotFoundError, subprocess.CalledProcessError):
            # gitleaks not available
            return findings

        try:
            # Write content to temporary file for gitleaks
            with tempfile.NamedTemporaryFile(mode='w', suffix=file_path.suffix, delete=False) as temp_file:
                temp_file.write(content)
                temp_file_path = temp_file.name

            try:
                # Run gitleaks detect
                result = subprocess.run(
                    ['gitleaks', 'detect', '--no-git', '--verbose', '--format', 'json'],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    cwd=os.path.dirname(temp_file_path)
                )

                if result.returncode == 0 and result.stdout:
                    # Parse gitleaks output (JSON lines format)
                    import json
                    for line in result.stdout.strip().split('\n'):
                        if line.strip():
                            try:
                                finding = json.loads(line)
                                if finding.get('file') == os.path.basename(temp_file_path):
                                    line_number = finding.get('line', 1)
                                    secret_type = finding.get('rule', 'secret')

                                    findings.append(Finding(
                                        id=f"gitleaks_{file_path.name}_{line_number}_{secret_type}",
                                        title="Hardcoded Secret Detected (gitleaks)",
                                        description=f"Potential hardcoded {secret_type} found",
                                        severity=Severity.CRITICAL,
                                        type=FindingType.SECURITY_ISSUE,
                                        location=Location(
                                            file=file_path,
                                            line_start=line_number,
                                            line_end=line_number
                                        ),
                                        checker_name=self.name,
                                        evidence=[Evidence(
                                            type="gitleaks",
                                            description=f"gitleaks detected {secret_type}",
                                            confidence=0.95,
                                            details=finding
                                        )],
                                        fixes=[Fix(
                                            type=FixType.PROMPT,
                                            description="Move secret to environment variables or secure configuration",
                                            prompt="Replace hardcoded secret with environment variable reference"
                                        )]
                                    ))
                            except json.JSONDecodeError:
                                pass  # Ignore JSON parsing errors

            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)

        except (subprocess.TimeoutExpired, subprocess.CalledProcessError):
            # gitleaks failed
            pass

        return findings

    def _check_with_regex(self, file_path: Path, content: str) -> List[Finding]:
        """Check file using regex patterns as fallback."""
        findings = []
        lines = content.splitlines()

        for line_number, line in enumerate(lines, 1):
            for pattern_name, pattern in self.secret_patterns.items():
                matches = pattern.findall(line)
                if matches:
                    for match in matches:
                        if isinstance(match, tuple):
                            # For patterns with groups, use the captured secret
                            secret_value = match[1] if len(match) > 1 else match[0]
                        else:
                            secret_value = match

                        # Skip obviously fake/test secrets
                        if self._is_likely_fake_secret(secret_value):
                            continue

                        findings.append(Finding(
                            id=f"regex_{file_path.name}_{line_number}_{pattern_name}",
                            title="Potential Hardcoded Secret Detected",
                            description=f"Found pattern matching {pattern_name.replace('_pattern', '').replace('_', ' ')}",
                            severity=Severity.HIGH,
                            type=FindingType.SECURITY_ISSUE,
                            location=Location(
                                file=file_path,
                                line_start=line_number,
                                line_end=line_number
                            ),
                            checker_name=self.name,
                            code_snippet=line.strip(),
                            evidence=[Evidence(
                                type="regex",
                                description=f"Regex pattern {pattern_name} matched",
                                confidence=0.7,
                                details={"pattern": pattern_name, "match": secret_value[:10] + "..."}
                            )],
                            fixes=[Fix(
                                type=FixType.PROMPT,
                                description="Move secret to environment variables or secure configuration",
                                prompt="Replace hardcoded secret with environment variable reference"
                            )]
                        ))

        return findings

    def _is_likely_fake_secret(self, secret: str) -> bool:
        """Check if a secret value looks like a fake/test value."""
        fake_indicators = [
            'your-', 'your_', 'example', 'test', 'dummy', 'fake', 'sample',
            'placeholder', 'changeme', 'password', '123456', 'abcdef',
            'xxxx', '****', 'sk-test', 'pk_test'
        ]

        secret_lower = secret.lower()
        return any(indicator in secret_lower for indicator in fake_indicators)
