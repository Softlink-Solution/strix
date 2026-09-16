---
name: mobile-ios-analysis
description: iOS application static analysis including Info.plist analysis, insecure storage inspection, hardcoded secrets detection, and API pinning bypass patterns
---

# iOS Application Static Analysis

This skill provides comprehensive methodologies for static analysis of iOS applications, focusing on security vulnerabilities in IPA files, configuration files, storage mechanisms, and communication patterns.

## Core Concepts

### iOS Security Architecture
- **Info.plist Analysis**: Analyze configuration files for security misconfigurations
- **Code Analysis**: Examine Swift/Objective-C code for security vulnerabilities
- **Storage Analysis**: Identify insecure data storage practices
- **Network Analysis**: Analyze network communication and certificate pinning
- **Entitlements Analysis**: Assess app entitlements for security issues

### Attack Vectors
- **Insecure Data Storage**: Sensitive data stored in insecure locations
- **Hardcoded Secrets**: API keys, passwords, and tokens in code
- **Weak Cryptography**: Usage of weak encryption algorithms
- **Entitlement Misuse**: Misconfigured app entitlements
- **Certificate Pinning Bypass**: SSL/TLS pinning vulnerabilities

## Safety and Authorization

### iOS Analysis Safety Rules
```python
class iOSSafetyValidator:
    """Safety validation for iOS application analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate iOS analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "iOS analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "ipa_analysis": self._validate_ipa_analysis,
            "code_analysis": self._validate_code_analysis,
            "storage_analysis": self._validate_storage_analysis,
            "entitlements_analysis": self._validate_entitlements_analysis
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_ipa_analysis(self, target: str) -> tuple[bool, str]:
        """Validate IPA analysis operations."""
        # Safety: Only analyze IPA structure, not modify or execute
        return True, "IPA structural analysis allowed in local lab mode"
    
    def _validate_code_analysis(self, target: str) -> tuple[bool, str]:
        """Validate code analysis operations."""
        # Safety: Only read-only code analysis
        return True, "Read-only code analysis allowed"
    
    def _validate_storage_analysis(self, target: str) -> tuple[bool, str]:
        """Validate storage analysis operations."""
        # Safety: Only analyze storage patterns, not access data
        return True, "Storage pattern analysis allowed"
    
    def _validate_entitlements_analysis(self, target: str) -> tuple[bool, str]:
        """Validate entitlements analysis operations."""
        # Safety: Only analyze entitlements configuration
        return True, "Entitlements analysis allowed"
```

## IPA Structure Analysis

### IPA Extraction and Analysis
```python
class IPAAnalyzer:
    """Analyze IPA file structure and contents."""
    
    def __init__(self, ipa_path: str):
        self.ipa_path = ipa_path
        self.extracted_path = None
    
    def extract_ipa(self) -> str:
        """Extract IPA contents for analysis."""
        try:
            # Safety: Extract to secure temporary location
            self.extracted_path = self._secure_extract(self.ipa_path)
            return self.extracted_path
        except Exception as e:
            return {"error": str(e), "safety_violation": "IPA extraction failed"}
    
    def analyze_info_plist(self) -> dict:
        """Analyze Info.plist for security issues."""
        plist_path = self._find_info_plist()
        
        try:
            plist_data = self._parse_plist(plist_path)
            security_analysis = {
                "app_permissions": self._analyze_permissions(plist_data),
                "url_schemes": self._analyze_url_schemes(plist_data),
                "security_settings": self._analyze_security_settings(plist_data),
                "bundle_configuration": self._analyze_bundle_config(plist_data),
                "background_modes": self._analyze_background_modes(plist_data),
                "app_transport_security": self._analyze_ats_settings(plist_data)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Info.plist analysis failed"}
    
    def _analyze_permissions(self, plist_data: dict) -> list[dict]:
        """Analyze requested permissions for security issues."""
        permissions = plist_data.get("NSBluetoothAlwaysUsageDescription", [])
        security_issues = []
        
        # Check for sensitive permissions
        sensitive_permissions = {
            "NSLocationAlwaysUsageDescription": "Always location access",
            "NSContactsUsageDescription": "Contacts access",
            "NSCameraUsageDescription": "Camera access",
            "NSMicrophoneUsageDescription": "Microphone access",
            "NSPhotoLibraryUsageDescription": "Photo library access"
        }
        
        for permission_key, description in sensitive_permissions.items():
            if permission_key in plist_data:
                security_issues.append({
                    "permission": permission_key,
                    "description": description,
                    "severity": "medium",
                    "recommendation": "Ensure permission is necessary and properly justified"
                })
        
        return security_issues
    
    def _analyze_url_schemes(self, plist_data: dict) -> list[dict]:
        """Analyze URL schemes for security issues."""
        url_schemes = plist_data.get("CFBundleURLTypes", [])
        security_issues = []
        
        for scheme_config in url_schemes:
            schemes = scheme_config.get("CFBundleURLSchemes", [])
            for scheme in schemes:
                # Check for insecure schemes
                if scheme.lower() in ["http", "ftp", "tel"]:
                    security_issues.append({
                        "scheme": scheme,
                        "severity": "medium",
                        "description": f"Insecure URL scheme: {scheme}",
                        "recommendation": "Use secure URL schemes where possible"
                    })
        
        return security_issues
    
    def _analyze_ats_settings(self, plist_data: dict) -> dict:
        """Analyze App Transport Security settings."""
        ats_config = plist_data.get("NSAppTransportSecurity", {})
        
        return {
            "ats_enabled": "NSAllowsArbitraryLoads" not in ats_config,
            "allows_arbitrary_loads": ats_config.get("NSAllowsArbitraryLoads", False),
            "allows_arbitrary_loads_in_web_content": ats_config.get("NSAllowsArbitraryLoadsInWebContent", False),
            "allows_local_networking": ats_config.get("NSAllowsLocalNetworking", False),
            "severity": "high" if ats_config.get("NSAllowsArbitraryLoads", False) else "info",
            "description": "ATS configuration analysis",
            "recommendation": "Disable arbitrary loads and configure specific exceptions"
        }
```

## Code Analysis

### Hardcoded Secrets Detection
```python
class iOSSecretsDetector:
    """Detect hardcoded secrets in iOS application code."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
        self.secret_patterns = self._compile_secret_patterns()
    
    def scan_for_secrets(self) -> list[dict]:
        """Scan application code for hardcoded secrets."""
        secrets_found = []
        
        # Scan Swift and Objective-C source files
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
class iOSCryptographyAnalyzer:
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
                "MD5", "SHA1", "md5", "sha1", "MD-5", "SHA-1",
                "CC_MD5", "CC_SHA1", "CommonCrypto"
            ],
            "weak_ciphers": [
                "DES", "3DES", "RC4", "DESede", "ARC4",
                "kCCAlgorithmDES", "kCCAlgorithm3DES", "kCCAlgorithmRC4"
            ],
            "weak_modes": [
                "ECB", "kCCModeECB"
            ],
            "insecure_random": [
                "arc4random", "rand", "random"
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
            "insecure_random": "Use SecRandomCopyBytes for cryptographic operations"
        }
        return recommendations.get(category, "Review cryptographic implementation")
```

## Storage Analysis

### Insecure Storage Detection
```python
class iOSStorageAnalyzer:
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
            
            # Check for UserDefaults
            if "UserDefaults" in content or "NSUserDefaults" in content:
                issues.append({
                    "type": "user_defaults",
                    "file": file_path,
                    "severity": "medium",
                    "description": "Application uses UserDefaults",
                    "recommendation": "Ensure sensitive data is encrypted before storing in UserDefaults"
                })
            
            # Check for Keychain
            if "Keychain" in content or "SecItem" in content:
                issues.append({
                    "type": "keychain_usage",
                    "file": file_path,
                    "severity": "info",
                    "description": "Application uses Keychain",
                    "recommendation": "Ensure Keychain is properly configured with appropriate accessibility"
                })
            
            # Check for Core Data
            if "CoreData" in content or "NSManagedObject" in content:
                issues.append({
                    "type": "core_data",
                    "file": file_path,
                    "severity": "medium",
                    "description": "Application uses Core Data",
                    "recommendation": "Ensure Core Data store is encrypted if it contains sensitive data"
                })
            
            # Check for file system storage
            if "Documents" in content or "Library" in content:
                issues.append({
                    "type": "file_system",
                    "file": file_path,
                    "severity": "medium",
                    "description": "Application uses file system storage",
                    "recommendation": "Ensure sensitive data is encrypted before storing to file system"
                })
            
            # Check for log statements with sensitive data
            if re.search(r'NSLog|print|os_log.*[Pp]assword', content):
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

## Entitlements Analysis

### Entitlements Security Analysis
```python
class EntitlementsAnalyzer:
    """Analyze app entitlements for security issues."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
    
    def analyze_entitlements(self) -> dict:
        """Analyze app entitlements configuration."""
        entitlements_path = self._find_entitlements_file()
        
        if not entitlements_path:
            return {
                "has_entitlements": False,
                "severity": "info",
                "description": "No entitlements file found"
            }
        
        try:
            entitlements_data = self._parse_plist(entitlements_path)
            security_analysis = {
                "has_entitlements": True,
                "dangerous_entitlements": self._identify_dangerous_entitlements(entitlements_data),
                "network_entitlements": self._analyze_network_entitlements(entitlements_data),
                "keychain_entitlements": self._analyze_keychain_entitlements(entitlements_data),
                "app_groups": self._analyze_app_groups(entitlements_data),
                "security_recommendations": self._generate_entitlement_recommendations(entitlements_data)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e)}
    
    def _identify_dangerous_entitlements(self, entitlements: dict) -> list[dict]:
        """Identify potentially dangerous entitlements."""
        dangerous_entitlements = []
        
        dangerous_keys = {
            "com.apple.security.cs.allow-jit": "Allows JIT compilation",
            "com.apple.security.cs.allow-unsigned-executable-memory": "Allows unsigned executable memory",
            "com.apple.security.cs.disable-library-validation": "Disables library validation",
            "com.apple.security.get-task-allow": "Allows debugger attachment",
            "com.apple.security.automation.apple-events": "Allows Apple events"
        }
        
        for key, description in dangerous_keys.items():
            if key in entitlements:
                dangerous_entitlements.append({
                    "entitlement": key,
                    "description": description,
                    "severity": "high",
                    "recommendation": "Review if this entitlement is necessary"
                })
        
        return dangerous_entitlements
    
    def _analyze_keychain_entitlements(self, entitlements: dict) -> dict:
        """Analyze Keychain access entitlements."""
        keychain_groups = entitlements.get("keychain-access-groups", [])
        
        return {
            "has_keychain_access": len(keychain_groups) > 0,
            "keychain_groups": keychain_groups,
            "shared_keychain": "com.apple.security.application-groups" in entitlements,
            "recommendation": "Review keychain access groups for necessary scope"
        }
```

## Network Analysis

### SSL/TLS Configuration Analysis
```python
class iOSNetworkAnalyzer:
    """Analyze network security configurations."""
    
    def __init__(self, extracted_path: str):
        self.extracted_path = extracted_path
    
    def analyze_network_security(self) -> dict:
        """Analyze network security configuration."""
        network_analysis = {
            "certificate_pinning": self._check_certificate_pinning(),
            "ats_configuration": self._analyze_ats_configuration(),
            "url_session_analysis": self._analyze_url_session_usage(),
            "third_party_networking": self._analyze_third_party_libraries()
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
                
                if "ServerTrustPolicy" in content or "Alamofire" in content:
                    has_pinning = True
                    pinning_type = "alamofire"
                    break
                elif "URLSessionDelegate" in content and "didReceive" in content:
                    has_pinning = True
                    pinning_type = "custom"
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
    
    def _analyze_ats_configuration(self) -> dict:
        """Analyze App Transport Security configuration."""
        plist_path = self._find_info_plist()
        
        try:
            plist_data = self._parse_plist(plist_path)
            ats_config = plist_data.get("NSAppTransportSecurity", {})
            
            return {
                "ats_enabled": "NSAllowsArbitraryLoads" not in ats_config,
                "allows_arbitrary_loads": ats_config.get("NSAllowsArbitraryLoads", False),
                "allows_arbitrary_loads_in_web_content": ats_config.get("NSAllowsArbitraryLoadsInWebContent", False),
                "allows_local_networking": ats_config.get("NSAllowsLocalNetworking", False),
                "domain_exceptions": ats_config.get("NSExceptionDomains", {}),
                "severity": "high" if ats_config.get("NSAllowsArbitraryLoads", False) else "info",
                "recommendation": "Configure ATS properly instead of disabling it"
            }
        except Exception as e:
            return {"error": str(e)}
```

## Analysis Methodology

### Phase 1: IPA Extraction and Structure Analysis
1. **IPA Extraction**: Extract IPA contents to secure location
2. **Info.plist Analysis**: Analyze configuration files for security issues
3. **Entitlements Analysis**: Review app entitlements
4. **Resource Analysis**: Examine resource files for sensitive data
5. **Binary Analysis**: Analyze compiled binary for security issues

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
- **Keychain**: Use iOS Keychain for storing sensitive data
- **Environment Variables**: Use environment variables for configuration
- **Code Review**: Implement code review processes to prevent secrets

### Insecure Storage
- **Use Keychain**: Use iOS Keychain for sensitive data
- **Encrypt Data**: Encrypt sensitive data before storage
- **Avoid UserDefaults**: Avoid storing sensitive data in UserDefaults
- **Proper Accessibility**: Use proper Keychain accessibility levels

### Weak Cryptography
- **Use Strong Algorithms**: Use modern, strong cryptographic algorithms
- **Use CryptoKit**: Use Apple's CryptoKit for cryptographic operations
- **Avoid Deprecated APIs**: Avoid deprecated cryptographic APIs
- **Keep Updated**: Keep cryptographic libraries updated

### Network Security
- **Implement Certificate Pinning**: Implement SSL/TLS certificate pinning
- **Configure ATS**: Properly configure App Transport Security
- **Use HTTPS**: Always use HTTPS for network communication
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

1. **Start with Info.plist**: Begin with Info.plist analysis for quick wins
2. **Automate Scanning**: Use automated tools for initial scanning
3. **Manual Review**: Conduct manual code review for complex issues
4. **Check Frameworks**: Analyze third-party frameworks for vulnerabilities
5. **Test Runtime**: Combine static analysis with dynamic testing
6. **Focus on High-Impact**: Prioritize high-impact vulnerabilities
7. **Document Everything**: Maintain detailed documentation of findings
8. **Update Regularly**: Keep analysis tools and patterns updated
9. **Review Dependencies**: Check CocoaPods/SPM for dependency vulnerabilities
10. **Consider Jailbreak**: Consider jailbreak detection and device integrity

## Summary

iOS application static analysis provides comprehensive security assessment of mobile applications through Info.plist analysis, code analysis, storage analysis, and network analysis. The combination of automated scanning and manual review enables identification of security vulnerabilities while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.