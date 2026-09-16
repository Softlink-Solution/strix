---
name: mobile-android-analysis
description: Android application static analysis including manifest analysis, insecure storage inspection, hardcoded secrets detection, and API pinning bypass patterns
---

# Android Application Static Analysis

This skill provides comprehensive methodologies for static analysis of Android applications, focusing on security vulnerabilities in APK files, manifest configurations, storage mechanisms, and communication patterns.

## Core Concepts

### Android Security Architecture
- **Manifest Analysis**: Analyze AndroidManifest.xml for security misconfigurations
- **Code Analysis**: Examine source code for security vulnerabilities
- **Storage Analysis**: Identify insecure data storage practices
- **Network Analysis**: Analyze network communication and certificate pinning
- **Component Analysis**: Assess app components for security issues

### Attack Vectors
- **Insecure Data Storage**: Sensitive data stored in insecure locations
- **Hardcoded Secrets**: API keys, passwords, and tokens in code
- **Weak Cryptography**: Usage of weak encryption algorithms
- **Component Exposure**: Exposed components leading to data leakage
- **Certificate Pinning Bypass**: SSL/TLS pinning vulnerabilities

## Safety and Authorization

### Mobile Analysis Safety Rules
```python
class MobileSafetyValidator:
    """Safety validation for mobile application analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate mobile analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "Mobile analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "apk_analysis": self._validate_apk_analysis,
            "code_analysis": self._validate_code_analysis,
            "storage_analysis": self._validate_storage_analysis,
            "network_analysis": self._validate_network_analysis
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_apk_analysis(self, target: str) -> tuple[bool, str]:
        """Validate APK analysis operations."""
        # Safety: Only analyze APK structure, not modify or execute
        return True, "APK structural analysis allowed in local lab mode"
    
    def _validate_code_analysis(self, target: str) -> tuple[bool, str]:
        """Validate code analysis operations."""
        # Safety: Only read-only code analysis
        return True, "Read-only code analysis allowed"
    
    def _validate_storage_analysis(self, target: str) -> tuple[bool, str]:
        """Validate storage analysis operations."""
        # Safety: Only analyze storage patterns, not access data
        return True, "Storage pattern analysis allowed"
    
    def _validate_network_analysis(self, target: str) -> tuple[bool, str]:
        """Validate network analysis operations."""
        # Safety: Only analyze network configuration, not intercept traffic
        return True, "Network configuration analysis allowed"
```

## APK Structure Analysis

### APK Decompilation and Analysis
```python
class APKAnalyzer:
    """Analyze APK file structure and contents."""
    
    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.extracted_path = None
    
    def extract_apk(self) -> str:
        """Extract APK contents for analysis."""
        try:
            # Safety: Extract to secure temporary location
            self.extracted_path = self._secure_extract(self.apk_path)
            return self.extracted_path
        except Exception as e:
            return {"error": str(e), "safety_violation": "APK extraction failed"}
    
    def analyze_manifest(self) -> dict:
        """Analyze AndroidManifest.xml for security issues."""
        manifest_path = f"{self.extracted_path}/AndroidManifest.xml"
        
        try:
            manifest = self._parse_manifest(manifest_path)
            security_analysis = {
                "permissions": self._analyze_permissions(manifest),
                "components": self._analyze_components(manifest),
                "security_configuration": self._analyze_security_config(manifest),
                "network_security": self._analyze_network_security(manifest),
                "exported_components": self._find_exported_components(manifest),
                "backup_configuration": self._check_backup_enabled(manifest),
                "debuggable": self._check_debuggable(manifest),
                "allow_backup": self._check_allow_backup(manifest)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Manifest analysis failed"}
    
    def _analyze_permissions(self, manifest: dict) -> list[dict]:
        """Analyze requested permissions for security issues."""
        permissions = manifest.get("permissions", [])
        security_issues = []
        
        dangerous_permissions = [
            "android.permission.READ_SMS",
            "android.permission.SEND_SMS",
            "android.permission.CALL_PHONE",
            "android.permission.READ_CONTACTS",
            "android.permission.ACCESS_FINE_LOCATION",
            "android.permission.RECORD_AUDIO",
            "android.permission.CAMERA"
        ]
        
        for permission in permissions:
            if permission in dangerous_permissions:
                security_issues.append({
                    "permission": permission,
                    "severity": "medium",
                    "description": "Dangerous permission requested",
                    "recommendation": "Ensure permission is necessary and properly justified"
                })
        
        return security_issues
    
    def _find_exported_components(self, manifest: dict) -> list[dict]:
        """Find exported components that may be vulnerable."""
        exported_components = []
        
        components = manifest.get("components", [])
        for component in components:
            if component.get("exported", False):
                exported_components.append({
                    "name": component.get("name"),
                    "type": component.get("type"),
                    "intent_filters": component.get("intent_filters", []),
                    "severity": "medium",
                    "description": "Component is exported and may be accessible by other apps",
                    "recommendation": "Review if export is necessary, implement proper permission checks"
                })
        
        return exported_components
    
    def _check_debuggable(self, manifest: dict) -> dict:
        """Check if application is debuggable."""
        application = manifest.get("application", {})
        debuggable = application.get("debuggable", False)
        
        return {
            "debuggable": debuggable,
            "severity": "high" if debuggable else "info",
            "description": "Application is debuggable" if debuggable else "Application is not debuggable",
            "recommendation": "Disable debuggable flag in production builds"
        }
    
    def _check_allow_backup(self, manifest: dict) -> dict:
        """Check if application allows backup."""
        application = manifest.get("application", {})
        allow_backup = application.get("allowBackup", True)
        
        return {
            "allow_backup": allow_backup,
            "severity": "medium" if allow_backup else "info",
            "description": "Application allows backup" if allow_backup else "Application does not allow backup",
            "recommendation": "Disable allowBackup if app handles sensitive data"
        }
```

## Code Analysis

### Hardcoded Secrets Detection
```python
class SecretsDetector:
    """Detect hardcoded secrets in application code."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
        self.secret_patterns = self._compile_secret_patterns()
    
    def scan_for_secrets(self) -> list[dict]:
        """Scan application code for hardcoded secrets."""
        secrets_found = []
        
        # Scan Java/Kotlin source files
        source_files = self._find_source_files()
        
        for source_file in source_files:
            file_secrets = self._scan_file_for_secrets(source_file)
            secrets_found.extend(file_secrets)
        
        return secrets_found
    
    def _compile_secret_patterns(self) -> dict:
        """Compile regex patterns for secret detection."""
        return {
            "api_keys": [
                r'[Aa][Pp][Ii][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
                r'[Ss][Ee][Cc][Rr][Ee][Tt][_-]?[Kk][Ee][Yy]\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']'
            ],
            "aws_keys": [
                r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
                r'[A-Za-z0-9/+=]{40}'  # AWS Secret Access Key pattern
            ],
            "google_keys": [
                r'AIza[A-Za-z0-9_\-]{35}',  # Google API Key
                r'[0-9a-f]{32}-[0-9a-f]{32}-[0-9a-f]{32}'  # Google OAuth client ID
            ],
            "tokens": [
                r'[Bb][Ee][Aa][Rr][Ee][Rr]\s+["\']([A-Za-z0-9_\-\.]{20,})["\']',
                r'[Tt][Oo][Kk][Ee][Nn]\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']'
            ],
            "passwords": [
                r'[Pp][Aa][Ss][Ss][Ww][Oo][Rr][Dd]\s*[:=]\s*["\']([^"\']{8,})["\']',
                r'[Pp][Ww][Dd]\s*[:=]\s*["\']([^"\']{8,})["\']'
            ],
            "database_urls": [
                r'[Mm][Yy][Ss][Qq][Ll]://[^:]+:[^@]+@[^/]+/[^\s]+',
                r'[Pp][Oo][Ss][Tt][Gg][Rr][Ee][Ss][Qq][Ll]://[^:]+:[^@]+@[^/]+/[^\s]+',
                r'[Mm][Oo][Nn][Gg][Oo][Dd][Bb]://[^:]+:[^@]+@[^/]+/[^\s]+'
            ]
        }
    
    def _scan_file_for_secrets(self, file_path: str) -> list[dict]:
        """Scan individual file for secrets."""
        secrets = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            for secret_type, patterns in self.secret_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content)
                    for match in matches:
                        secret_value = match.group(1) if match.groups() else match.group(0)
                        secrets.append({
                            "type": secret_type,
                            "value": self._mask_secret(secret_value),
                            "file": file_path,
                            "line": content[:match.start()].count('\n') + 1,
                            "severity": self._assess_secret_severity(secret_type, secret_value),
                            "recommendation": self._get_secret_recommendation(secret_type)
                        })
        except Exception as e:
            pass  # Skip files that can't be read
        
        return secrets
    
    def _mask_secret(self, secret: str) -> str:
        """Mask secret value for safe reporting."""
        if len(secret) <= 4:
            return "***"
        return secret[:2] + "*" * (len(secret) - 4) + secret[-2:]
    
    def _assess_secret_severity(self, secret_type: str, secret_value: str) -> str:
        """Assess severity of found secret."""
        high_severity_types = ["api_keys", "aws_keys", "google_keys", "database_urls"]
        
        if secret_type in high_severity_types:
            return "critical"
        elif secret_type == "tokens":
            return "high"
        else:
            return "medium"
```

### Weak Cryptography Detection
```python
class CryptographyAnalyzer:
    """Analyze cryptographic implementations for weaknesses."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
        self.weak_algorithms = self._compile_weak_algorithms()
    
    def analyze_cryptography(self) -> list[dict]:
        """Analyze cryptographic implementations."""
        issues = []
        
        source_files = self._find_source_files()
        
        for source_file in source_files:
            file_issues = self._analyze_file_cryptography(source_file)
            issues.extend(file_issues)
        
        return issues
    
    def _compile_weak_algorithms(self) -> dict:
        """Compile list of weak cryptographic algorithms."""
        return {
            "weak_hashes": [
                "MD5", "SHA1", "md5", "sha1", "MD-5", "SHA-1"
            ],
            "weak_ciphers": [
                "DES", "3DES", "RC4", "DESede", "ARC4"
            ],
            "weak_modes": [
                "ECB", "PKCS5Padding", "PKCS7Padding"
            ],
            "insecure_random": [
                "java.util.Random", "java.lang.Math.random"
            ]
        }
    
    def _analyze_file_cryptography(self, file_path: str) -> list[dict]:
        """Analyze cryptographic usage in file."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for weak algorithms
            for category, algorithms in self.weak_algorithms.items():
                for algorithm in algorithms:
                    if algorithm in content:
                        issues.append({
                            "category": category,
                            "algorithm": algorithm,
                            "file": file_path,
                            "severity": "high",
                            "description": f"Usage of weak cryptographic algorithm: {algorithm}",
                            "recommendation": self._get_crypto_recommendation(category, algorithm)
                        })
        except Exception as e:
            pass
        
        return issues
    
    def _get_crypto_recommendation(self, category: str, algorithm: str) -> str:
        """Get recommendation for weak cryptographic usage."""
        recommendations = {
            "weak_hashes": "Use SHA-256 or stronger for hashing",
            "weak_ciphers": "Use AES-256 or stronger encryption",
            "weak_modes": "Use authenticated encryption modes like GCM",
            "insecure_random": "Use SecureRandom for cryptographic operations"
        }
        return recommendations.get(category, "Review cryptographic implementation")
```

## Storage Analysis

### Insecure Storage Detection
```python
class StorageAnalyzer:
    """Analyze data storage practices for security issues."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
    
    def analyze_storage(self) -> list[dict]:
        """Analyze data storage patterns."""
        storage_issues = []
        
        source_files = self._find_source_files()
        
        for source_file in source_files:
            file_issues = self._analyze_file_storage(source_file)
            storage_issues.extend(file_issues)
        
        return storage_issues
    
    def _analyze_file_storage(self, file_path: str) -> list[dict]:
        """Analyze storage patterns in file."""
        issues = []
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Check for SharedPreferences
            if "SharedPreferences" in content:
                issues.append({
                    "type": "shared_preferences",
                    "file": file_path,
                    "severity": "medium",
                    "description": "Application uses SharedPreferences",
                    "recommendation": "Ensure sensitive data is encrypted before storing in SharedPreferences"
                })
            
            # Check for external storage
            if "Environment.getExternalStorageDirectory()" in content or \
               "Environment.getExternalStoragePublicDirectory()" in content:
                issues.append({
                    "type": "external_storage",
                    "file": file_path,
                    "severity": "high",
                    "description": "Application uses external storage",
                    "recommendation": "Avoid storing sensitive data on external storage, or encrypt it"
                })
            
            # Check for SQLite databases
            if "SQLiteDatabase" in content or "SQLiteOpenHelper" in content:
                issues.append({
                    "type": "sqlite_database",
                    "file": file_path,
                    "severity": "medium",
                    "description": "Application uses SQLite database",
                    "recommendation": "Ensure database is encrypted if it contains sensitive data"
                })
            
            # Check for log statements with sensitive data
            if re.search(r'Log\.[dew]\([^)]*[Pp]assword[^)]*\)', content):
                issues.append({
                    "type": "sensitive_logging",
                    "file": file_path,
                    "severity": "high",
                    "description": "Application may log sensitive data",
                    "recommendation": "Remove sensitive data from log statements"
                })
            
        except Exception as e:
            pass
        
        return issues
```

## Network Analysis

### SSL/TLS Configuration Analysis
```python
class NetworkAnalyzer:
    """Analyze network security configurations."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
    
    def analyze_network_security(self) -> dict:
        """Analyze network security configuration."""
        network_analysis = {
            "certificate_pinning": self._check_certificate_pinning(),
            "https_usage": self._check_https_usage(),
            "cleartext_traffic": self._check_cleartext_traffic(),
            "network_security_config": self._analyze_network_security_config(),
            "ssl_context_analysis": self._analyze_ssl_context()
        }
        return network_analysis
    
    def _check_certificate_pinning(self) -> dict:
        """Check for certificate pinning implementation."""
        source_files = self._find_source_files()
        has_pinning = False
        pinning_type = None
        
        for source_file in source_files:
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                if "CertificatePinner" in content or "okhttp3.CertificatePinner" in content:
                    has_pinning = True
                    pinning_type = "okhttp"
                    break
                elif "network_security_config" in content.lower():
                    has_pinning = True
                    pinning_type = "android_security_config"
                    break
            except Exception as e:
                pass
        
        return {
            "has_pinning": has_pinning,
            "pinning_type": pinning_type,
            "severity": "medium" if not has_pinning else "info",
            "description": "Certificate pinning not implemented" if not has_pinning else "Certificate pinning implemented",
            "recommendation": "Implement certificate pinning to prevent MITM attacks" if not has_pinning else "Review pinning implementation"
        }
    
    def _check_cleartext_traffic(self) -> dict:
        """Check if cleartext traffic is allowed."""
        manifest_path = f"{self.extracted_path}/AndroidManifest.xml"
        
        try:
            manifest = self._parse_manifest(manifest_path)
            application = manifest.get("application", {})
            uses_cleartext_traffic = application.get("usesCleartextTraffic", False)
            
            return {
                "allows_cleartext": uses_cleartext_traffic,
                "severity": "high" if uses_cleartext_traffic else "info",
                "description": "Application allows cleartext traffic" if uses_cleartext_traffic else "Application does not allow cleartext traffic",
                "recommendation": "Disable cleartext traffic in production" if uses_cleartext_traffic else "Good security practice"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_network_security_config(self) -> dict:
        """Analyze network security configuration file."""
        config_path = f"{self.extracted_path}/res/xml/network_security_config.xml"
        
        if not os.path.exists(config_path):
            return {
                "has_config": False,
                "severity": "medium",
                "description": "No network security configuration file found",
                "recommendation": "Implement network security configuration"
            }
        
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config_content = f.read()
            
            config_analysis = {
                "has_config": True,
                "pinning_configured": "pin-set" in config_content,
                "cleartext_allowed": "cleartextTrafficPermitted" in config_content and "true" in config_content,
                "debug_overrides": "debug-overrides" in config_content,
                "domain_configurations": self._extract_domain_configs(config_content)
            }
            
            return config_analysis
        except Exception as e:
            return {"error": str(e)}
```

## Analysis Methodology

### Phase 1: APK Extraction and Structure Analysis
1. **APK Extraction**: Extract APK contents to secure location
2. **Manifest Analysis**: Analyze AndroidManifest.xml for security issues
3. **Permission Analysis**: Review requested permissions
4. **Component Analysis**: Analyze exported components
5. **Resource Analysis**: Examine resource files for sensitive data

### Phase 2: Code Analysis
1. **Secrets Detection**: Scan for hardcoded secrets and credentials
2. **Cryptography Analysis**: Analyze cryptographic implementations
3. **Storage Analysis**: Identify insecure data storage practices
4. **Network Analysis**: Analyze network communication patterns
5. **Code Review**: Manual code review for security issues

### Phase 3: Security Assessment
1. **Vulnerability Scoring**: Score identified vulnerabilities
2. **Risk Assessment**: Assess overall security risk
3. **Remediation Planning**: Prioritize remediation efforts
4. **Report Generation**: Generate comprehensive security report
5. **Recommendations**: Provide actionable security recommendations

## Remediation Guidance

### Hardcoded Secrets
- **Remove Secrets**: Remove hardcoded secrets from source code
- **Environment Variables**: Use environment variables or secure storage
- **Key Management**: Use proper key management systems
- **Code Review**: Implement code review processes to prevent secrets

### Insecure Storage
- **Encrypt Data**: Encrypt sensitive data before storage
- **Use Secure Storage**: Use Android Keystore for sensitive data
- **Avoid External Storage**: Avoid storing sensitive data on external storage
- **Clear Data**: Implement proper data clearing mechanisms

### Weak Cryptography
- **Use Strong Algorithms**: Use modern, strong cryptographic algorithms
- **Avoid Deprecated Methods**: Avoid deprecated cryptographic methods
- **Use Standard Libraries**: Use well-vetted cryptographic libraries
- **Keep Updated**: Keep cryptographic libraries updated

### Network Security
- **Implement Certificate Pinning**: Implement SSL/TLS certificate pinning
- **Use HTTPS**: Always use HTTPS for network communication
- **Disable Cleartext Traffic**: Disable cleartext traffic in production
- **Validate Certificates**: Implement proper certificate validation

## Safety Compliance

### Operational Boundaries
- **Read-Only Analysis**: All operations are read-only analysis
- **No Execution**: No execution of application code
- **Safe Extraction**: Extract to secure temporary locations
- **Data Protection**: Protect sensitive findings during analysis
- **Local Lab Only**: Strictly limited to authorized local lab environments

### Ethical Guidelines
- **Authorized Apps**: Only analyze authorized applications
- **Privacy Protection**: Protect user privacy during analysis
- **Data Protection**: Securely handle sensitive findings
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Minimal Impact**: Use techniques that minimize operational impact

## Pro Tips

1. **Start with Manifest**: Begin with manifest analysis for quick wins
2. **Automate Scanning**: Use automated tools for initial scanning
3. **Manual Review**: Conduct manual code review for complex issues
4. **Check Libraries**: Analyze third-party libraries for vulnerabilities
5. **Test Runtime**: Combine static analysis with dynamic testing
6. **Focus on High-Impact**: Prioritize high-impact vulnerabilities
7. **Document Everything**: Maintain detailed documentation of findings
8. **Update Regularly**: Keep analysis tools and patterns updated
9. **Review Gradle**: Check Gradle files for dependency vulnerabilities
10. **Consider Root**: Consider root detection and jailbreak detection

## Summary

Android application static analysis provides comprehensive security assessment of mobile applications through manifest analysis, code analysis, storage analysis, and network analysis. The combination of automated scanning and manual review enables identification of security vulnerabilities while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.