"""Classical checker for validating dependencies against PyPI to prevent malware."""

import re
import json
import tomli
from pathlib import Path
from typing import List, Dict, Set, Optional, Tuple
from urllib.parse import urljoin

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence

try:
    import httpx
    HAS_HTTPX = True
except ImportError:
    HAS_HTTPX = False


class DependencyValidationChecker(BaseChecker):
    """Checker for validating dependencies against PyPI to prevent malware downloads."""

    def __init__(self):
        super().__init__(
            name="dependency_validation",
            description="Validates dependencies against PyPI to prevent malware downloads",
            is_classical=True
        )

        # PyPI API base URL
        self.pypi_base_url = "https://pypi.org/pypi/"
        self.pypi_simple_api = "https://pypi.org/simple/"

        # File patterns to check
        self.dependency_files = {
            'requirements.txt': self._parse_requirements_txt,
            'requirements-dev.txt': self._parse_requirements_txt,
            'requirements-prod.txt': self._parse_requirements_txt,
            'pyproject.toml': self._parse_pyproject_toml,
            'setup.py': self._parse_setup_py,
            'setup.cfg': self._parse_setup_cfg,
            'Pipfile': self._parse_pipfile,
            'Pipfile.lock': self._parse_pipfile_lock,
            'package.json': self._parse_package_json,
            'package-lock.json': self._parse_package_lock_json,
            'yarn.lock': self._parse_yarn_lock,
        }

        # Package name patterns for different ecosystems
        self.package_name_patterns = {
            'python': re.compile(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])$'),
            'javascript': re.compile(r'^(@[a-zA-Z0-9][a-zA-Z0-9._/-]*[a-zA-Z0-9]|[a-zA-Z][a-zA-Z0-9._/-]*[a-zA-Z0-9])$'),
        }

        # Cache for package existence checks
        self._package_cache: Dict[str, bool] = {}

    def _get_supported_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return ['.txt', '.toml', '.py', '.cfg', '.lock', '.json']

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Check a dependency file for potentially malicious packages."""
        findings = []

        # Check if this is a dependency file we support
        file_name = file_path.name
        if file_name not in self.dependency_files:
            return findings

        try:
            # Parse the dependency file
            parser_func = self.dependency_files[file_name]
            packages = parser_func(content)

            # Validate each package
            for package_name, version_spec, line_number in packages:
                validation_findings = self._validate_package(
                    package_name, version_spec, file_path, line_number, file_name
                )
                findings.extend(validation_findings)

        except Exception as e:
            # Report parsing errors
            findings.append(Finding(
                id=f"parse_error_{file_path.name}",
                title="Dependency File Parse Error",
                description=f"Failed to parse dependency file: {str(e)}",
                severity=Severity.MEDIUM,
                type=FindingType.BAD_PRACTICE,
                location=Location(file=file_path, line_start=1),
                checker_name=self.name,
                evidence=[Evidence(
                    type="parsing",
                    description=f"Exception during parsing: {str(e)}",
                    confidence=1.0
                )]
            ))

        return findings

    def _validate_package(self, package_name: str, version_spec: str,
                         file_path: Path, line_number: int, file_type: str) -> List[Finding]:
        """Validate a single package against PyPI."""
        findings = []

        # Skip validation if httpx is not available
        if not HAS_HTTPX:
            findings.append(Finding(
                id=f"no_httpx_{file_path.name}_{line_number}",
                title="Cannot Validate Dependencies",
                description="httpx library not available - cannot validate packages against PyPI",
                severity=Severity.LOW,
                type=FindingType.BAD_PRACTICE,
                location=Location(file=file_path, line_start=line_number),
                checker_name=self.name,
                evidence=[Evidence(
                    type="dependency",
                    description="httpx library required for PyPI validation",
                    confidence=1.0
                )]
            ))
            return findings

        # Determine ecosystem based on file type
        ecosystem = self._get_ecosystem(file_type)

        # Basic package name validation
        if not self._is_valid_package_name(package_name, ecosystem):
            findings.append(Finding(
                id=f"invalid_package_name_{file_path.name}_{line_number}_{package_name}",
                title="Invalid Package Name",
                description=f"Package name '{package_name}' does not match expected pattern for {ecosystem}",
                severity=Severity.MEDIUM,
                type=FindingType.SECURITY_ISSUE,
                location=Location(file=file_path, line_start=line_number),
                checker_name=self.name,
                evidence=[Evidence(
                    type="pattern",
                    description=f"Package name validation failed for {ecosystem} ecosystem",
                    confidence=0.9
                )]
            ))
            return findings

        # Check if package exists on PyPI (for Python packages)
        if ecosystem == 'python':
            exists = self._check_package_exists_pypi(package_name)
            if not exists:
                findings.append(Finding(
                    id=f"nonexistent_package_{file_path.name}_{line_number}_{package_name}",
                    title="Potentially Malicious Package",
                    description=f"Package '{package_name}' does not exist on PyPI. This could be malware or a typo.",
                    severity=Severity.CRITICAL,
                    type=FindingType.SECURITY_ISSUE,
                    location=Location(file=file_path, line_start=line_number),
                    checker_name=self.name,
                    evidence=[Evidence(
                        type="pypi_api",
                        description=f"Package '{package_name}' not found on PyPI",
                        confidence=0.95
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Remove or replace the suspicious package",
                        prompt=f"Verify if '{package_name}' is a legitimate package. If it's a typo, correct it. If suspicious, remove it immediately."
                    )]
                ))

        return findings

    def _get_ecosystem(self, file_type: str) -> str:
        """Determine the package ecosystem based on file type."""
        if file_type in ['requirements.txt', 'requirements-dev.txt', 'requirements-prod.txt',
                        'pyproject.toml', 'setup.py', 'setup.cfg', 'Pipfile', 'Pipfile.lock']:
            return 'python'
        elif file_type in ['package.json', 'package-lock.json', 'yarn.lock']:
            return 'javascript'
        else:
            return 'unknown'

    def _is_valid_package_name(self, package_name: str, ecosystem: str) -> bool:
        """Check if package name matches expected pattern for ecosystem."""
        if ecosystem not in self.package_name_patterns:
            return True  # Allow unknown ecosystems

        pattern = self.package_name_patterns[ecosystem]
        return bool(pattern.match(package_name))

    def _check_package_exists_pypi(self, package_name: str) -> bool:
        """Check if a package exists on PyPI."""
        # Check cache first
        if package_name in self._package_cache:
            return self._package_cache[package_name]

        try:
            # Use httpx to check PyPI API
            with httpx.Client(timeout=10.0) as client:
                # Try the JSON API first
                url = f"{self.pypi_base_url}{package_name}/json"
                response = client.get(url)

                if response.status_code == 200:
                    self._package_cache[package_name] = True
                    return True
                elif response.status_code == 404:
                    # Package doesn't exist
                    self._package_cache[package_name] = False
                    return False
                else:
                    # Try the simple API as fallback
                    simple_url = f"{self.pypi_simple_api}{package_name}/"
                    simple_response = client.get(simple_url)

                    exists = simple_response.status_code == 200
                    self._package_cache[package_name] = exists
                    return exists

        except Exception as e:
            # If we can't check, assume it exists to avoid false positives
            # But log the issue for debugging
            print(f"Warning: Could not check PyPI for {package_name}: {e}")
            return True

    def _parse_requirements_txt(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse requirements.txt style files."""
        packages = []
        lines = content.splitlines()

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue

            # Extract package name (handle version specs)
            # Examples: package==1.0.0, package>=1.0.0, package[extras]
            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])(.*)', line)
            if match:
                package_name = match.group(1)
                version_spec = match.group(2).strip()
                packages.append((package_name, version_spec, line_num))

        return packages

    def _parse_pyproject_toml(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse pyproject.toml files."""
        packages = []

        try:
            data = tomli.loads(content)

            # Check [project.dependencies]
            if 'project' in data and 'dependencies' in data['project']:
                deps = data['project']['dependencies']
                for dep in deps:
                    # Parse dependency spec (e.g., "requests>=2.25.0")
                    match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])(.*)', dep)
                    if match:
                        packages.append((match.group(1), match.group(2).strip(), 0))  # Line number not available

            # Check [tool.poetry.dependencies]
            if 'tool' in data and 'poetry' in data['tool'] and 'dependencies' in data['tool']['poetry']:
                deps = data['tool']['poetry']['dependencies']
                for dep_name in deps.keys():
                    if dep_name != 'python':  # Skip python version spec
                        version_spec = deps[dep_name]
                        packages.append((dep_name, str(version_spec), 0))

        except Exception as e:
            print(f"Warning: Could not parse pyproject.toml: {e}")

        return packages

    def _parse_setup_py(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse setup.py files (basic regex-based parsing)."""
        packages = []

        # Look for install_requires patterns
        install_requires_pattern = re.compile(
            r'install_requires\s*=\s*\[(.*?)\]',
            re.DOTALL
        )

        match = install_requires_pattern.search(content)
        if match:
            deps_str = match.group(1)

            # Extract individual dependencies
            dep_pattern = re.compile(r'["\']([^"\']+)["\']')
            for dep_match in dep_pattern.finditer(deps_str):
                dep = dep_match.group(1)
                match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])(.*)', dep)
                if match:
                    packages.append((match.group(1), match.group(2).strip(), 0))

        return packages

    def _parse_setup_cfg(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse setup.cfg files."""
        packages = []

        # Look for [options] install_requires
        lines = content.splitlines()
        in_install_requires = False

        for line_num, line in enumerate(lines, 1):
            line = line.strip()

            if line == '[options]' or line.startswith('[options]'):
                continue

            if line.startswith('install_requires'):
                in_install_requires = True
                # Handle inline format: install_requires = package==1.0.0
                if '=' in line:
                    _, deps_str = line.split('=', 1)
                    deps_str = deps_str.strip()
                    if deps_str.startswith('['):
                        # Multi-line format
                        in_install_requires = True
                    else:
                        # Single line format
                        deps = [d.strip().strip('"\'') for d in deps_str.split(',')]
                        for dep in deps:
                            match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])(.*)', dep)
                            if match:
                                packages.append((match.group(1), match.group(2).strip(), line_num))
                continue

            if in_install_requires:
                if line.startswith('['):
                    continue
                elif line.startswith(']'):
                    in_install_requires = False
                else:
                    # Parse dependency line
                    dep = line.strip().strip(',"\'')
                    if dep:
                        match = re.match(r'^([a-zA-Z0-9][a-zA-Z0-9._-]*[a-zA-Z0-9]|[a-zA-Z0-9])(.*)', dep)
                        if match:
                            packages.append((match.group(1), match.group(2).strip(), line_num))

        return packages

    def _parse_pipfile(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse Pipfile (TOML format)."""
        packages = []

        try:
            data = tomli.loads(content)

            # Check [packages] section
            if 'packages' in data:
                for dep_name, version_spec in data['packages'].items():
                    packages.append((dep_name, str(version_spec), 0))

            # Check [dev-packages] section
            if 'dev-packages' in data:
                for dep_name, version_spec in data['dev-packages'].items():
                    packages.append((dep_name, str(version_spec), 0))

        except Exception as e:
            print(f"Warning: Could not parse Pipfile: {e}")

        return packages

    def _parse_pipfile_lock(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse Pipfile.lock (JSON format)."""
        packages = []

        try:
            data = json.loads(content)

            # Check _meta section for locked packages
            if '_meta' in data and 'version' in data['_meta']:
                # This is a Pipfile.lock file
                for section_name in ['develop', 'default']:
                    if section_name in data:
                        for dep_name in data[section_name].keys():
                            version_info = data[section_name][dep_name]
                            if isinstance(version_info, dict) and 'version' in version_info:
                                version_spec = version_info['version']
                                packages.append((dep_name, version_spec, 0))

        except Exception as e:
            print(f"Warning: Could not parse Pipfile.lock: {e}")

        return packages

    def _parse_package_json(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse package.json files."""
        packages = []

        try:
            data = json.loads(content)

            # Check dependencies
            for dep_type in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
                if dep_type in data:
                    for dep_name, version_spec in data[dep_type].items():
                        packages.append((dep_name, version_spec, 0))

        except Exception as e:
            print(f"Warning: Could not parse package.json: {e}")

        return packages

    def _parse_package_lock_json(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse package-lock.json files."""
        packages = []

        try:
            data = json.loads(content)

            # Check dependencies section
            if 'dependencies' in data:
                for dep_name, dep_info in data['dependencies'].items():
                    if 'version' in dep_info:
                        packages.append((dep_name, dep_info['version'], 0))

        except Exception as e:
            print(f"Warning: Could not parse package-lock.json: {e}")

        return packages

    def _parse_yarn_lock(self, content: str) -> List[Tuple[str, str, int]]:
        """Parse yarn.lock files (basic parsing)."""
        packages = []

        lines = content.splitlines()
        current_package = None

        for line in lines:
            line = line.strip()

            # Package name lines start with package name followed by @
            if '@' in line and not line.startswith('  '):
                # Extract package name before @
                match = re.match(r'^([^@\s]+)@', line)
                if match:
                    current_package = match.group(1)
            elif current_package and line.startswith('  version'):
                # Version line
                match = re.match(r'  version\s+"([^"]+)"', line)
                if match:
                    version = match.group(1)
                    packages.append((current_package, version, 0))
                    current_package = None

        return packages
