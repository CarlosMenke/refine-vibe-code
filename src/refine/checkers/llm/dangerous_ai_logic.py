"""Hybrid checker for detecting dangerous AI logic and unsafe ML practices.

Combines classical pattern matching with LLM analysis to identify potentially
harmful AI/ML code patterns including security vulnerabilities, unsafe model
usage, data poisoning risks, and other dangerous AI practices.
"""

import re
import ast
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional

from ..base import BaseChecker
from refine.core.results import Finding, Severity, FindingType, Location, Fix, FixType, Evidence
from refine.providers import get_provider


class DangerousAILogicChecker(BaseChecker):
    """Hybrid checker for dangerous AI logic and unsafe ML practices."""

    def __init__(self):
        super().__init__(
            name="dangerous_ai_logic",
            description="Detects dangerous AI/ML logic, security vulnerabilities, and unsafe practices",
            is_classical=False  # Hybrid with LLM enhancement
        )

        # AI/ML framework imports to detect
        self.ai_frameworks = {
            'tensorflow', 'tf', 'torch', 'pytorch', 'keras', 'sklearn', 'scikit-learn',
            'transformers', 'huggingface', 'openai', 'anthropic', 'cohere', 'replicate',
            'onnx', 'xgboost', 'lightgbm', 'catboost', 'mlflow', 'wandb', 'tensorboard'
        }

        # Dangerous patterns for classical analysis
        self.dangerous_patterns = [
            # Model loading from untrusted sources
            re.compile(r'load_model\s*\(\s*["\']https?://', re.IGNORECASE),
            re.compile(r'torch\.load\s*\(\s*["\']https?://', re.IGNORECASE),
            re.compile(r'tf\.saved_model\.load\s*\(\s*["\']https?://', re.IGNORECASE),

            # Hardcoded API keys in AI contexts
            re.compile(r'(openai|anthropic|cohere).*api[_-]?key\s*[=:]\s*["\'][^"\']{10,}["\']', re.IGNORECASE),
            re.compile(r'(huggingface|hf).*token\s*[=:]\s*["\'][^"\']{10,}["\']', re.IGNORECASE),

            # Unsafe pickle usage with ML models
            re.compile(r'pickle\.load\s*\(\s*open\s*\(', re.IGNORECASE),
            re.compile(r'torch\.load\s*\([^,)]*\)\s*$', re.IGNORECASE),  # torch.load without weights_only

            # Direct execution of model outputs
            re.compile(r'eval\s*\(\s*\w*\.predict|\.generate|\.completion', re.IGNORECASE),
            re.compile(r'exec\s*\(\s*\w*\.predict|\.generate|\.completion', re.IGNORECASE),

            # Unbounded loops in training/validation
            re.compile(r'while\s+True\s*:\s*[^}]*\.(fit|train|predict)', re.IGNORECASE),

            # No validation of model inputs
            re.compile(r'\.predict\s*\([^)]*\)\s*$', re.IGNORECASE),  # predict without input validation

            # Hardcoded model paths
            re.compile(r'(model|weights|checkpoint).*["\']\s*[=:]\s*["\']/?[^\s"\']*["\']', re.IGNORECASE),
        ]

        # Contextual patterns that suggest dangerous AI practices
        self.contextual_dangers = [
            # Data poisoning vulnerabilities
            re.compile(r'def.*train.*data.*:\s*[^}]*input\(\)', re.IGNORECASE | re.DOTALL),
            re.compile(r'def.*load.*data.*:\s*[^}]*open\s*\(\s*.*input\(\)', re.IGNORECASE | re.DOTALL),

            # Model inversion risks - only flag suspicious patterns, not legitimate uses
            re.compile(r'def.*extract.*data.*model', re.IGNORECASE),  # Only flag explicit extract functions
            re.compile(r'send.*model.*parameters|send.*state_dict', re.IGNORECASE),  # Only flag sending over network

            # Unsafe model serialization
            re.compile(r'with\s+open\s*\(\s*.*model.*\)\s+as\s+\w+:\s*[^}]*pickle\.dump', re.IGNORECASE | re.DOTALL),

            # No input sanitization before model inference
            re.compile(r'\.predict\s*\(\s*request\.|\.args|\.form|\.data', re.IGNORECASE),
        ]

        # Variables that suggest user-controlled inputs
        self.user_input_indicators = [
            'user_input', 'user_data', 'input_data', 'request', 'args', 'form',
            'data', 'payload', 'query', 'params', 'body', 'files', 'upload'
        ]

    def _get_supported_extensions(self) -> List[str]:
        """Return supported file extensions."""
        return ['.py', '.ipynb', '.pyw']

    def check_file(self, file_path: Path, content: str) -> List[Finding]:
        """Check a file for dangerous AI logic and unsafe ML practices."""
        findings = []

        # Skip if file doesn't contain AI/ML related code
        if not self._has_ai_frameworks(content):
            return findings

        try:
            # Classical pattern-based analysis
            classical_findings = self._classical_analysis(content, file_path)
            findings.extend(classical_findings)

            # AST-based analysis for structural issues
            ast_findings = self._ast_analysis(content, file_path)
            findings.extend(ast_findings)

            # LLM analysis for deeper dangerous AI logic detection
            llm_findings = self._llm_analysis(content, file_path)
            findings.extend(llm_findings)

        except SyntaxError:
            # If file has syntax errors, still try basic pattern matching
            pattern_findings = self._pattern_based_analysis(content, file_path)
            findings.extend(pattern_findings)

        return findings

    def _has_ai_frameworks(self, content: str) -> bool:
        """Check if the file contains AI/ML framework imports or usage."""
        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if line.startswith(('import ', 'from ', 'importlib.import_module')):
                for framework in self.ai_frameworks:
                    if framework in line.lower():
                        return True

            # Also check for common AI/ML function calls
            if any(func in line.lower() for func in ['.fit(', '.predict(', '.train(', '.evaluate(']):
                return True

        return False

    def _classical_analysis(self, content: str, file_path: Path) -> List[Finding]:
        """Perform classical pattern-based analysis for dangerous AI patterns."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_content = line.strip()

            # Check dangerous patterns
            for pattern in self.dangerous_patterns:
                if pattern.search(line_content):
                    severity, title, description = self._classify_dangerous_pattern(pattern, line_content)

                    findings.append(Finding(
                        id=f"dangerous_ai_classical_{file_path.name}_{i}_{hash(line_content) % 1000}",
                        title=title,
                        description=description,
                        severity=severity,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(file=file_path, line_start=i, line_end=i),
                        checker_name=self.name,
                        code_snippet=line_content,
                        evidence=[Evidence(
                            type="pattern_match",
                            description=f"Matched dangerous AI pattern: {pattern.pattern}",
                            confidence=0.8
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description="Fix dangerous AI practice",
                            prompt=self._get_fix_prompt_for_pattern(pattern, line_content)
                        )]
                    ))
                    break  # Only report once per line

            # Check contextual dangers
            for pattern in self.contextual_dangers:
                if pattern.search(line_content):
                    severity, title, description = self._classify_contextual_danger(pattern, line_content)

                    findings.append(Finding(
                        id=f"dangerous_ai_contextual_{file_path.name}_{i}_{hash(line_content) % 1000}",
                        title=title,
                        description=description,
                        severity=severity,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(file=file_path, line_start=i, line_end=i),
                        checker_name=self.name,
                        code_snippet=line_content,
                        evidence=[Evidence(
                            type="contextual_pattern",
                            description=f"Detected contextual AI danger: {pattern.pattern}",
                            confidence=0.75
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description="Address contextual AI security issue",
                            prompt=self._get_fix_prompt_for_contextual(pattern, line_content)
                        )]
                    ))
                    break  # Only report once per line

        return findings

    def _classify_dangerous_pattern(self, pattern: re.Pattern, line: str) -> Tuple[Severity, str, str]:
        """Classify the severity and description of a dangerous pattern."""
        pattern_str = pattern.pattern.lower()

        if 'api' in pattern_str and 'key' in pattern_str:
            return (Severity.CRITICAL, "Hardcoded AI API Key Detected",
                   "AI service API key is hardcoded in source code, creating security vulnerability")
        elif 'load_model' in pattern_str or 'torch.load' in pattern_str or 'pickle.load' in pattern_str:
            return (Severity.HIGH, "Unsafe Model Loading",
                   "Model loading from potentially untrusted source without validation")
        elif 'eval' in pattern_str or 'exec' in pattern_str:
            return (Severity.CRITICAL, "Dangerous Code Execution from AI Output",
                   "Direct execution of AI model output can lead to code injection attacks")
        elif 'while true' in pattern_str:
            return (Severity.MEDIUM, "Potential Infinite Training Loop",
                   "Unbounded training loop may cause resource exhaustion")
        else:
            return (Severity.MEDIUM, "Potentially Dangerous AI Pattern",
                   "Detected pattern that may indicate unsafe AI/ML practice")

    def _classify_contextual_danger(self, pattern: re.Pattern, line: str) -> Tuple[Severity, str, str]:
        """Classify contextual AI dangers."""
        pattern_str = pattern.pattern.lower()

        if 'input(' in pattern_str and 'train' in pattern_str:
            return (Severity.CRITICAL, "Data Poisoning Vulnerability",
                   "Training data loaded directly from user input without validation")
        elif 'pickle.dump' in pattern_str:
            return (Severity.HIGH, "Unsafe Model Serialization",
                   "Model serialized with pickle, vulnerable to deserialization attacks")
        elif 'extract.*data.*model' in pattern_str:
            return (Severity.HIGH, "Model Inversion Risk",
                   "Code attempts to extract training data from model, potential privacy violation")
        elif '.predict' in pattern_str and ('request' in pattern_str or 'args' in pattern_str):
            return (Severity.MEDIUM, "Unvalidated Model Input",
                   "Model prediction called with unsanitized user input")
        else:
            return (Severity.LOW, "Potentially Risky AI Context",
                   "Context suggests potential AI security or safety concern")

    def _get_fix_prompt_for_pattern(self, pattern: re.Pattern, line: str) -> str:
        """Get appropriate fix prompt for dangerous patterns."""
        pattern_str = pattern.pattern.lower()

        if 'api' in pattern_str and 'key' in pattern_str:
            return "Move API key to environment variables or secure configuration management system"
        elif 'load_model' in pattern_str or 'torch.load' in pattern_str:
            return "Implement proper model validation and use safe loading methods with integrity checks"
        elif 'eval' in pattern_str or 'exec' in pattern_str:
            return "Never execute AI model output directly. Implement safe evaluation or use whitelisting"
        elif 'pickle.load' in pattern_str:
            return "Avoid pickle for model serialization. Use safer alternatives like joblib or custom serialization"
        elif 'while true' in pattern_str:
            return "Add proper termination conditions and resource limits to training loops"
        else:
            return "Review this AI/ML code pattern for potential security and safety issues"

    def _get_fix_prompt_for_contextual(self, pattern: re.Pattern, line: str) -> str:
        """Get fix prompts for contextual dangers."""
        pattern_str = pattern.pattern.lower()

        if 'input(' in pattern_str and 'train' in pattern_str:
            return "Implement proper data validation, sanitization, and source verification before training"
        elif 'pickle.dump' in pattern_str:
            return "Use secure serialization methods instead of pickle for model persistence"
        elif 'extract.*data.*model' in pattern_str:
            return "Avoid attempts to extract training data from models. Implement proper privacy safeguards"
        elif '.predict' in pattern_str and ('request' in pattern_str or 'args' in pattern_str):
            return "Add input validation, sanitization, and bounds checking before model inference"
        else:
            return "Review this AI/ML code for security and safety best practices"

    def _ast_analysis(self, content: str, file_path: Path) -> List[Finding]:
        """Perform AST-based analysis for structural dangerous AI patterns."""
        findings = []

        try:
            tree = ast.parse(content, filename=str(file_path))

            class DangerousAIVisitor(ast.NodeVisitor):
                def __init__(self, checker, file_path: Path, content: str):
                    self.checker = checker
                    self.file_path = file_path
                    self.content = content
                    self.lines = content.splitlines()
                    self.findings = []

                def visit_FunctionDef(self, node):
                    # Check for dangerous function patterns
                    self._check_dangerous_function(node)
                    self.generic_visit(node)

                def visit_Call(self, node):
                    # Check for dangerous function calls
                    self._check_dangerous_calls(node)
                    self.generic_visit(node)

                def _check_dangerous_function(self, node):
                    """Check function definitions for dangerous AI patterns."""
                    func_name = node.name.lower()

                    # Check for functions that might be vulnerable to data poisoning
                    if any(keyword in func_name for keyword in ['train', 'fit', 'load_data', 'preprocess']):
                        # Look for direct user input usage
                        for child in ast.walk(node):
                            if isinstance(child, ast.Call) and isinstance(child.func, ast.Name):
                                if child.func.id == 'input':
                                    line_no = node.lineno
                                    self.findings.append(Finding(
                                        id=f"dangerous_ai_ast_func_{line_no}_{func_name}",
                                        title="Data Poisoning Risk in Training Function",
                                        description=f"Training/preprocessing function '{node.name}' uses direct user input, vulnerable to data poisoning",
                                        severity=Severity.HIGH,
                                        type=FindingType.SECURITY_ISSUE,
                                        location=Location(file=self.file_path, line_start=line_no, line_end=node.end_lineno or line_no),
                                        checker_name="dangerous_ai_logic",
                                        code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                                        evidence=[Evidence(
                                            type="ast_analysis",
                                            description="Function definition contains direct input() calls in AI training context",
                                            confidence=0.9
                                        )],
                                        fixes=[Fix(
                                            type=FixType.PROMPT,
                                            description="Implement secure data loading",
                                            prompt="Replace direct input() calls with validated data sources and implement data sanitization"
                                        )]
                                    ))
                                    break

                def _check_dangerous_calls(self, node):
                    """Check function calls for dangerous AI patterns."""
                    if isinstance(node.func, ast.Attribute):
                        # Check for model.predict() without input validation
                        if node.func.attr == 'predict' and len(node.args) > 0:
                            # Check if first argument looks like user input
                            first_arg = node.args[0]
                            if self._looks_like_user_input(first_arg):
                                line_no = node.lineno
                                self.findings.append(Finding(
                                    id=f"dangerous_ai_ast_predict_{line_no}",
                                    title="Unvalidated Model Input",
                                    description="Model prediction called with potentially unsanitized user input",
                                    severity=Severity.MEDIUM,
                                    type=FindingType.SECURITY_ISSUE,
                                    location=Location(file=self.file_path, line_start=line_no, line_end=line_no),
                                    checker_name="dangerous_ai_logic",
                                    code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                                    evidence=[Evidence(
                                        type="ast_analysis",
                                        description="predict() method called with user input variable",
                                        confidence=0.8
                                    )],
                                    fixes=[Fix(
                                        type=FixType.PROMPT,
                                        description="Add input validation",
                                        prompt="Implement input validation, sanitization, and bounds checking before model prediction"
                                    )]
                                ))

                    elif isinstance(node.func, ast.Name):
                        # Check for dangerous standalone function calls
                        if node.func.id in ['eval', 'exec']:
                            # Check if argument comes from AI model output
                            for arg in node.args:
                                if self._looks_like_ai_output(arg):
                                    line_no = node.lineno
                                    self.findings.append(Finding(
                                        id=f"dangerous_ai_ast_eval_{line_no}",
                                        title="Dangerous Code Execution from AI Output",
                                        description=f"{node.func.id}() called with potential AI model output, creating code injection vulnerability",
                                        severity=Severity.CRITICAL,
                                        type=FindingType.SECURITY_ISSUE,
                                        location=Location(file=self.file_path, line_start=line_no, line_end=line_no),
                                        checker_name="dangerous_ai_logic",
                                        code_snippet=self.lines[line_no - 1] if line_no <= len(self.lines) else "",
                                        evidence=[Evidence(
                                            type="ast_analysis",
                                            description=f"{node.func.id}() called with AI model output",
                                            confidence=0.95
                                        )],
                                        fixes=[Fix(
                                            type=FixType.PROMPT,
                                            description="Remove dangerous code execution",
                                            prompt=f"Never use {node.func.id}() with AI model outputs. Implement safe evaluation or whitelisting"
                                        )]
                                    ))
                                    break

                def _looks_like_user_input(self, node) -> bool:
                    """Check if an AST node looks like user input."""
                    if isinstance(node, ast.Name):
                        var_name = node.id.lower()
                        return any(indicator in var_name for indicator in self.checker.user_input_indicators)
                    elif isinstance(node, ast.Attribute):
                        # Check attribute access like request.data, args.input, etc.
                        attr_chain = self._get_attribute_chain(node)
                        attr_str = '.'.join(attr_chain).lower()
                        return any(indicator in attr_str for indicator in self.checker.user_input_indicators)
                    return False

                def _looks_like_ai_output(self, node) -> bool:
                    """Check if an AST node looks like AI model output."""
                    if isinstance(node, ast.Name):
                        var_name = node.id.lower()
                        return any(keyword in var_name for keyword in ['prediction', 'output', 'result', 'response', 'completion'])
                    elif isinstance(node, ast.Attribute):
                        # Check method calls like model.predict(), ai.generate(), etc.
                        if isinstance(node.value, ast.Name):
                            caller = node.value.id.lower()
                            method = node.attr.lower()
                            return (caller in ['model', 'ai', 'assistant'] and
                                   method in ['predict', 'generate', 'complete', 'chat'])
                    elif isinstance(node, ast.Call):
                        # Check nested calls
                        if isinstance(node.func, ast.Attribute):
                            return self._looks_like_ai_output(node.func)
                    return False

                def _get_attribute_chain(self, node) -> List[str]:
                    """Get the full attribute access chain."""
                    chain = []
                    current = node
                    while isinstance(current, ast.Attribute):
                        chain.insert(0, current.attr)
                        current = current.value
                    if isinstance(current, ast.Name):
                        chain.insert(0, current.id)
                    return chain

            visitor = DangerousAIVisitor(self, file_path, content)
            visitor.visit(tree)
            findings.extend(visitor.findings)

        except SyntaxError:
            pass

        return findings

    def _llm_analysis(self, content: str, file_path: Path) -> List[Finding]:
        """Use LLM for deeper analysis of dangerous AI logic patterns."""
        findings = []

        try:
            provider = get_provider()

            # If provider is not available, skip LLM analysis
            if not provider.is_available():
                return findings

            # Create analysis prompt
            prompt = self._create_llm_prompt(content, file_path)

            # Get LLM analysis
            response = provider.analyze_code(prompt)

            # Parse response and create findings
            llm_findings = self._parse_llm_response(response, file_path, content)
            findings.extend(llm_findings)

        except Exception:
            # If LLM analysis fails, continue without it
            pass

        return findings

    def _create_llm_prompt(self, content: str, file_path: Path) -> str:
        """Create a prompt for LLM analysis of dangerous AI logic."""
        return f"""Analyze this Python code for dangerous AI logic, security vulnerabilities, and unsafe ML practices. Focus on:

1. SECURITY VULNERABILITIES:
   - API keys hardcoded in AI/ML code
   - Unsafe model loading from untrusted sources
   - Code injection through AI model outputs
   - Data poisoning attack vectors
   - Model inversion risks (only when training data is being extracted for malicious purposes, not legitimate uses like optimizer initialization or model saving)

2. UNSAFE AI PRACTICES:
   - No input validation before model inference
   - Blind trust in model outputs
   - Resource exhaustion (infinite loops, unbounded training)
   - Poor error handling in AI pipelines
   - Lack of model validation or monitoring

3. PRIVACY & ETHICAL CONCERNS:
   - Potential bias amplification
   - Privacy violations through model outputs
   - Unintended data leakage
   - Lack of consent or transparency

4. TECHNICAL RISKS:
   - Model serialization/deserialization vulnerabilities
   - Unsafe use of eval/exec with AI outputs
   - Lack of adversarial input testing

IMPORTANT: Do NOT flag legitimate uses of model.parameters() or model.state_dict() for optimizer initialization, model saving/loading, or checkpointing. These are standard ML practices.

Code file: {file_path.name}

Code:
```python
{content}
```

Provide your analysis in the following JSON format:
{{
  "vulnerabilities": [
    {{
      "type": "security_vulnerability|unsafe_practice|privacy_risk|technical_risk",
      "severity": "critical|high|medium|low",
      "title": "Brief, descriptive title",
      "description": "Detailed explanation of the dangerous AI logic or vulnerability",
      "line_number": 42,
      "confidence": 0.85,
      "category": "security|privacy|ethics|technical",
      "recommendation": "Specific fix or mitigation strategy"
    }}
  ],
  "overall_risk_assessment": "Brief summary of AI safety and security concerns"
}}

Focus on actual dangerous patterns. If no significant issues are found, return an empty vulnerabilities array."""

    def _parse_llm_response(self, response: str, file_path: Path, content: str) -> List[Finding]:
        """Parse LLM response and create findings."""
        findings = []
        lines = content.splitlines()

        try:
            import json

            # Try to extract JSON from response
            json_start = response.find('{')
            json_end = response.rfind('}') + 1
            if json_start >= 0 and json_end > json_start:
                json_response = response[json_start:json_end]
                data = json.loads(json_response)

                for vuln in data.get('vulnerabilities', []):
                    line_no = vuln.get('line', 1)
                    vuln_type = vuln.get('type', 'dangerous_ai')
                    severity_str = vuln.get('severity', 'medium')
                    title = vuln.get('title', 'Dangerous AI Logic Detected')
                    description = vuln.get('description', 'LLM detected dangerous AI/ML practice')
                    recommendation = vuln.get('recommendation', 'Review and fix this AI safety issue')

                    # Map string severity to enum
                    severity_map = {
                        'low': Severity.LOW,
                        'medium': Severity.MEDIUM,
                        'high': Severity.HIGH,
                        'critical': Severity.CRITICAL
                    }
                    severity = severity_map.get(severity_str.lower(), Severity.MEDIUM)

                    finding = Finding(
                        id=f"dangerous_ai_llm_{file_path.name}_{line_no}_{hash(title) % 1000}",
                        title=title,
                        description=description,
                        severity=severity,
                        type=FindingType.SECURITY_ISSUE,
                        location=Location(
                            file=file_path,
                            line_start=line_no,
                            line_end=line_no
                        ),
                        checker_name=self.name,
                        evidence=[Evidence(
                            type="llm_analysis",
                            description=f"LLM detected {vuln_type}: {description}",
                            confidence=float(vuln.get("confidence", 0.8)),
                            details=vuln
                        )],
                        fixes=[Fix(
                            type=FixType.PROMPT,
                            description=f"Fix {vuln_type}",
                            prompt=recommendation
                        )],
                        code_snippet=lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                    )
                    findings.append(finding)

        except (json.JSONDecodeError, KeyError, IndexError):
            # If JSON parsing fails, try to extract basic information
            pass

        return findings

    def _pattern_based_analysis(self, content: str, file_path: Path) -> List[Finding]:
        """Fallback pattern-based analysis for dangerous AI patterns."""
        findings = []
        lines = content.splitlines()

        for i, line in enumerate(lines, 1):
            line_content = line.strip()

            # Simple pattern checks for critical issues
            if 'eval(' in line_content and any(keyword in line_content.lower() for keyword in ['predict', 'generate', 'response']):
                findings.append(Finding(
                    id=f"dangerous_ai_fallback_eval_{i}",
                    title="Critical: Code Execution from AI Output",
                    description="Code uses eval() with AI model output, creating severe security vulnerability",
                    severity=Severity.CRITICAL,
                    type=FindingType.SECURITY_ISSUE,
                    location=Location(file=file_path, line_start=i, line_end=i),
                    checker_name=self.name,
                    code_snippet=line_content,
                    evidence=[Evidence(
                        type="pattern_fallback",
                        description="eval() used with AI model output",
                        confidence=0.9
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Remove dangerous eval usage",
                        prompt="Never use eval() with AI model outputs. Implement safe alternatives."
                    )]
                ))

            elif 'exec(' in line_content and any(keyword in line_content.lower() for keyword in ['predict', 'generate', 'response']):
                findings.append(Finding(
                    id=f"dangerous_ai_fallback_exec_{i}",
                    title="Critical: Code Execution from AI Output",
                    description="Code uses exec() with AI model output, creating severe security vulnerability",
                    severity=Severity.CRITICAL,
                    type=FindingType.SECURITY_ISSUE,
                    location=Location(file=file_path, line_start=i, line_end=i),
                    checker_name=self.name,
                    code_snippet=line_content,
                    evidence=[Evidence(
                        type="pattern_fallback",
                        description="exec() used with AI model output",
                        confidence=0.9
                    )],
                    fixes=[Fix(
                        type=FixType.PROMPT,
                        description="Remove dangerous exec usage",
                        prompt="Never use exec() with AI model outputs. Implement safe alternatives."
                    )]
                ))

        return findings
