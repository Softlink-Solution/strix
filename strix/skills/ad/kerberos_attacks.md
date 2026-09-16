---
name: ad-kerberos-attacks
description: Kerberos attack methodologies including Kerberoasting, AS-REP roasting, Golden/Silver ticket attacks, and delegation abuse
---

# Kerberos Attack Methodologies

This skill provides advanced Kerberos attack techniques for identifying and exploiting Kerberos protocol vulnerabilities in Active Directory environments.

## Core Concepts

### Kerberos Protocol Fundamentals
- **Ticket Granting Ticket (TGT)**: Initial authentication ticket
- **Service Ticket (TGS)**: Ticket for accessing specific services
- **Key Distribution Center (KDC)**: Domain Controller handling Kerberos
- **Pre-Authentication**: Security measure to prevent offline cracking
- **Delegation**: Service-to-service authentication capability

### Attack Vectors
- **Kerberoasting**: Requesting service tickets for offline cracking
- **AS-REP Roasting**: Exploiting disabled pre-authentication
- **Golden Ticket**: Creating forged TGTs using KRBTGT hash
- **Silver Ticket**: Creating forged service tickets
- **Delegation Abuse**: Exploiting unconstrained/constrained delegation

## Safety and Authorization

### Critical Safety Requirements
```python
class KerberosSafetyValidator:
    """Safety validation for Kerberos attack operations."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate Kerberos operation against safety rules."""
        
        # Strict local lab requirement
        if not self.governance.is_local_lab:
            return False, "Kerberos attacks only allowed in local_lab mode"
        
        # Target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific restrictions
        dangerous_operations = ["golden_ticket", "silver_ticket", "dcsync"]
        if operation in dangerous_operations:
            return False, f"{operation} requires explicit authorization and monitoring"
        
        return True, f"{operation} allowed in authorized local lab environment"
```

## Kerberoasting

### Identification of Kerberoastable Accounts
```python
class KerberoastIdentifier:
    """Identify accounts vulnerable to Kerberoasting."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def find_kerberoastable_accounts(self) -> list[dict]:
        """Find service accounts with SPNs (Kerberoastable)."""
        vulnerable_accounts = []
        
        # Find accounts with SPNs
        ldap_filter = "(servicePrincipalName=*)"
        attributes = ["sAMAccountName", "servicePrincipalName", "pwdLastSet", 
                     "userAccountControl", "memberOf", "distinguishedName"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        for account in results:
            if self._is_kerberoastable(account):
                account_info = {
                    "username": account.get("sAMAccountName"),
                    "spns": account.get("servicePrincipalName"),
                    "password_last_set": self._convert_ad_timestamp(account.get("pwdLastSet")),
                    "account_disabled": self._is_account_disabled(account),
                    "privilege_level": self._assess_privilege_level(account),
                    "groups": account.get("memberOf", []),
                    "severity": self._calculate_severity(account),
                    "remediation": self._get_remediation_recommendation(account)
                }
                vulnerable_accounts.append(account_info)
        
        return vulnerable_accounts
    
    def _is_kerberoastable(self, account: dict) -> bool:
        """Determine if account is Kerberoastable."""
        # Account must have SPN and not be disabled
        has_spn = bool(account.get("servicePrincipalName"))
        not_disabled = not self._is_account_disabled(account)
        return has_spn and not_disabled
    
    def _assess_privilege_level(self, account: dict) -> str:
        """Assess the privilege level of the account."""
        groups = account.get("memberOf", [])
        
        high_privilege_groups = ["Domain Admins", "Enterprise Admins", "Administrators"]
        for group in groups:
            if any(priv_group in group for priv_group in high_privilege_groups):
                return "high"
        
        return "medium"
    
    def _calculate_severity(self, account: dict) -> str:
        """Calculate severity based on account characteristics."""
        privilege = self._assess_privilege_level(account)
        password_age = self._get_password_age(account)
        
        if privilege == "high" and password_age > 90:
            return "critical"
        elif privilege == "high":
            return "high"
        elif password_age > 180:
            return "high"
        else:
            return "medium"
```

### Service Ticket Request (Safe Analysis)
```python
class KerberoastAnalyzer:
    """Analyze Kerberoast vulnerabilities (safe, read-only)."""
    
    def __init__(self, domain_controller: str, domain: str):
        self.dc = domain_controller
        self.domain = domain
    
    def request_service_ticket_analysis(self, spn: str) -> dict:
        """Request service ticket for analysis (metadata only)."""
        try:
            # Safety: Only collect ticket metadata, not crack tickets
            ticket_metadata = self._get_ticket_metadata(spn)
            
            analysis = {
                "spn": spn,
                "ticket_type": ticket_metadata.get("etype"),
                "ticket_size": ticket_metadata.get("size"),
                "timestamp": ticket_metadata.get("timestamp"),
                "account_age": ticket_metadata.get("account_age"),
                "password_complexity": ticket_metadata.get("password_complexity"),
                "vulnerability_assessment": self._assess_vulnerability(ticket_metadata),
                "remediation_priority": self._get_remediation_priority(ticket_metadata),
                "safety_status": "read_only_analysis"
            }
            
            return analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Ticket analysis failed"}
    
    def assess_kerberoast_risk(self, accounts: list[dict]) -> dict:
        """Assess overall Kerberoast risk for identified accounts."""
        risk_assessment = {
            "total_kerberoastable": len(accounts),
            "high_privilege_accounts": len([a for a in accounts if a.get("privilege_level") == "high"]),
            "old_passwords": len([a for a in accounts if a.get("password_age_days", 0) > 90]),
            "risk_score": self._calculate_risk_score(accounts),
            "recommendations": self._generate_recommendations(accounts)
        }
        return risk_assessment
```

## AS-REP Roasting

### AS-REP Roastable Account Identification
```python
class ASREPRoastIdentifier:
    """Identify accounts vulnerable to AS-REP roasting."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def find_asrep_roastable_accounts(self) -> list[dict]:
        """Find accounts with Kerberos pre-auth disabled."""
        vulnerable_accounts = []
        
        # Find accounts with UF_DONT_REQUIRE_PREAUTH flag (4194304)
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        attributes = ["sAMAccountName", "distinguishedName", "userAccountControl",
                     "memberOf", "pwdLastSet"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        for account in results:
            account_info = {
                "username": account.get("sAMAccountName"),
                "dn": account.get("distinguishedName"),
                "account_disabled": self._is_account_disabled(account),
                "password_last_set": self._convert_ad_timestamp(account.get("pwdLastSet")),
                "groups": account.get("memberOf", []),
                "severity": "high",
                "description": "Account has Kerberos pre-authentication disabled",
                "remediation": "Enable Kerberos pre-authentication unless required"
            }
            vulnerable_accounts.append(account_info)
        
        return vulnerable_accounts
    
    def check_preauth_status(self, username: str) -> dict:
        """Check pre-authentication status for specific account."""
        ldap_filter = f"(sAMAccountName={username})"
        attributes = ["userAccountControl", "distinguishedName"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        if results:
            account = results[0]
            uac = int(account.get("userAccountControl", 0))
            preauth_disabled = bool(uac & 4194304)
            
            return {
                "username": username,
                "preauth_disabled": preauth_disabled,
                "vulnerable": preauth_disabled,
                "uac_flags": uac,
                "remediation": "Enable Kerberos pre-authentication" if preauth_disabled else "Account secure"
            }
        
        return {"error": "Account not found"}
```

## Delegation Attacks

### Unconstrained Delegation Analysis
```python
class UnconstrainedDelegationAnalyzer:
    """Analyze unconstrained delegation configurations."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def find_unconstrained_delegation_accounts(self) -> list[dict]:
        """Find accounts with unconstrained delegation."""
        vulnerable_accounts = []
        
        # Find accounts with UF_TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION flag (524288)
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        attributes = ["sAMAccountName", "objectClass", "distinguishedName", "servicePrincipalName"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        for account in results:
            account_type = "computer" if "computer" in account.get("objectClass", []) else "user"
            
            account_info = {
                "name": account.get("sAMAccountName"),
                "type": account_type,
                "dn": account.get("distinguishedName"),
                "spns": account.get("servicePrincipalName", []),
                "severity": "high" if account_type == "computer" else "medium",
                "attack_vector": "Service ticket abuse for TGT delegation",
                "remediation": "Constrain delegation or remove unconstrained delegation flag"
            }
            vulnerable_accounts.append(account_info)
        
        return vulnerable_accounts
    
    def assess_delegation_risk(self, accounts: list[dict]) -> dict:
        """Assess overall delegation risk."""
        computers = [a for a in accounts if a.get("type") == "computer"]
        users = [a for a in accounts if a.get("type") == "user"]
        
        return {
            "total_unconstrained": len(accounts),
            "computers": len(computers),
            "users": len(users),
            "high_risk_targets": [a["name"] for a in computers],
            "risk_score": len(computers) * 10 + len(users) * 5,
            "recommendations": [
                "Review unconstrained delegation necessity",
                "Constrain delegation where possible",
                "Monitor for suspicious TGT requests",
                "Consider protected accounts"
            ]
        }
```

### Resource-Based Constrained Delegation (RBCD)
```python
class RBCDAnalyzer:
    """Analyze resource-based constrained delegation configurations."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def find_rbcd_misconfigurations(self) -> list[dict]:
        """Find computers with writable RBCD attributes."""
        misconfigurations = []
        
        # Find computers and check msDS-AllowedToActOnBehalfOfOtherIdentity attribute
        ldap_filter = "(objectClass=computer)"
        attributes = ["sAMAccountName", "distinguishedName", "objectSid"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        for computer in results:
            computer_dn = computer.get("distinguishedName")
            
            # Check if low-privileged users can write to RBCD attribute
            if self._has_writable_rbcd_attribute(computer_dn):
                misconfigurations.append({
                    "computer": computer.get("sAMAccountName"),
                    "dn": computer_dn,
                    "severity": "high",
                    "description": "Computer has writable RBCD attribute",
                    "remediation": "Restrict write permissions on msDS-AllowedToActOnBehalfOfOtherIdentity"
                })
        
        return misconfigurations
    
    def _has_writable_rbcd_attribute(self, computer_dn: str) -> bool:
        """Check if computer has writable RBCD attribute."""
        # Safety: Check only ACL permissions, not modify
        acl = self.ldap._get_acl(computer_dn)
        
        # Check for generic write permissions
        for ace in acl:
            if self._has_generic_write_permission(ace):
                return True
        
        return False
```

## Golden Ticket Analysis (Read-Only)

### KRBTGT Account Analysis
```python
class GoldenTicketAnalyzer:
    """Analyze Golden Ticket attack surface (read-only)."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def analyze_krbtgt_account(self) -> dict:
        """Analyze KRBTGT account security (read-only)."""
        krbtgt_info = {}
        
        # Find KRBTGT account
        ldap_filter = "(sAMAccountName=krbtgt)"
        attributes = ["pwdLastSet", "lastLogon", "distinguishedName", "userAccountControl"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        if results:
            krbtgt = results[0]
            krbtgt_info = {
                "account_found": True,
                "password_last_set": self._convert_ad_timestamp(krbtgt.get("pwdLastSet")),
                "last_logon": self._convert_ad_timestamp(krbtgt.get("lastLogon")),
                "account_disabled": self._is_account_disabled(krbtgt),
                "password_age_days": self._get_password_age(krbtgt),
                "security_recommendation": self._get_krbtgt_recommendation(krbtgt),
                "safety_status": "read_only_analysis"
            }
        else:
            krbtgt_info = {
                "account_found": False,
                "error": "KRBTGT account not found"
            }
        
        return krbtgt_info
    
    def _get_krbtgt_recommendation(self, krbtgt: dict) -> str:
        """Get security recommendation for KRBTGT account."""
        password_age = self._get_password_age(krbtgt)
        
        if password_age > 180:
            return "CRITICAL: KRBTGT password should be rotated immediately (age > 180 days)"
        elif password_age > 90:
            return "HIGH: KRBTGT password should be rotated (age > 90 days)"
        else:
            return "Consider regular KRBTGT password rotation as per security policy"
```

## Silver Ticket Analysis (Read-Only)

### Service Account Analysis
```python
class SilverTicketAnalyzer:
    """Analyze Silver Ticket attack surface (read-only)."""
    
    def __init__(self, ldap_enumerator):
        self.ldap = ldap_enumerator
    
    def analyze_service_accounts(self) -> list[dict]:
        """Analyze service accounts for Silver Ticket risk."""
        service_accounts = []
        
        # Find service accounts with SPNs
        ldap_filter = "(servicePrincipalName=*)"
        attributes = ["sAMAccountName", "servicePrincipalName", "pwdLastSet", 
                     "userAccountControl", "memberOf"]
        
        results = self.ldap._ldap_search(ldap_filter, attributes)
        
        for account in results:
            if self._is_high_value_service(account):
                account_info = {
                    "username": account.get("sAMAccountName"),
                    "spns": account.get("servicePrincipalName"),
                    "password_last_set": self._convert_ad_timestamp(account.get("pwdLastSet")),
                    "privilege_level": self._assess_privilege_level(account),
                    "silver_ticket_risk": self._assess_silver_ticket_risk(account),
                    "remediation": self._get_service_account_recommendation(account)
                }
                service_accounts.append(account_info)
        
        return service_accounts
    
    def _is_high_value_service(self, account: dict) -> bool:
        """Identify high-value service accounts."""
        spns = account.get("servicePrincipalName", [])
        high_value_services = ["MSSQLSvc", "HTTP", "cifs", "HOST", "LDAP"]
        
        for spn in spns:
            if any(service in spn for service in high_value_services):
                return True
        
        return False
```

## Attack Methodology

### Phase 1: Vulnerability Identification
1. **Kerberoastable Accounts**: Identify service accounts with SPNs
2. **AS-REP Roastable Accounts**: Find accounts with pre-auth disabled
3. **Delegation Analysis**: Map unconstrained and constrained delegation
4. **KRBTGT Analysis**: Assess KRBTGT account security
5. **Service Account Analysis**: Identify high-value service accounts

### Phase 2: Risk Assessment
1. **Password Age Analysis**: Assess password age and rotation policies
2. **Privilege Level Assessment**: Evaluate account privilege levels
3. **Attack Path Mapping**: Map potential attack paths
4. **Risk Scoring**: Calculate overall risk scores
5. **Remediation Prioritization**: Prioritize remediation efforts

### Phase 3: Security Hardening
1. **Enable Pre-Authentication**: Enable Kerberos pre-auth where appropriate
2. **Constrain Delegation**: Move from unconstrained to constrained delegation
3. **Password Rotation**: Implement regular password rotation
4. **Service Account Management**: Implement proper service account lifecycle
5. **Monitoring**: Implement monitoring for suspicious Kerberos activity

## Remediation Guidance

### Kerberoasting Remediation
- **Strong Passwords**: Use strong, complex passwords for service accounts
- **Regular Rotation**: Implement regular password rotation
- **Least Privilege**: Use least privilege for service accounts
- **Group Managed Service Accounts**: Use gMSAs where possible
- **Monitoring**: Monitor for unusual service ticket requests

### AS-REP Roasting Remediation
- **Enable Pre-Authentication**: Enable Kerberos pre-authentication
- **Account Review**: Review accounts that legitimately need pre-auth disabled
- **Monitoring**: Monitor for AS-REP requests
- **Documentation**: Document exceptions for pre-auth disabled accounts

### Delegation Remediation
- **Constrain Delegation**: Use constrained delegation instead of unconstrained
- **Resource-Based Delegation**: Use RBCD where appropriate
- **Protected Accounts**: Protect high-privilege accounts from delegation abuse
- **Monitoring**: Monitor for delegation-related attacks

## Safety Compliance

### Operational Boundaries
- **Read-Only Analysis**: All operations are read-only for analysis
- **No Credential Extraction**: No extraction or cracking of credentials
- **Local Lab Only**: Strictly limited to authorized local lab environments
- **Audit Trail**: All operations logged for compliance
- **Authorization Required**: Explicit authorization required for advanced operations

### Ethical Guidelines
- **Authorized Testing**: Only test authorized domain environments
- **Minimal Impact**: Use techniques that minimize operational impact
- **No Production Exploitation**: Never exploit vulnerabilities in production
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Privacy Protection**: Protect user privacy during security assessment

## Pro Tips

1. **Start with Enumeration**: Begin with comprehensive enumeration before attack analysis
2. **Focus on High-Value Targets**: Prioritize high-privilege service accounts
3. **Check Delegation**: Delegation misconfigurations are common attack vectors
4. **Monitor Password Age**: Old passwords indicate security issues
5. **Use BloodHound**: Leverage BloodHound for comprehensive attack path analysis
6. **Document Findings**: Maintain detailed documentation for remediation
7. **Assess Impact**: Consider business impact when prioritizing remediation
8. **Implement Monitoring**: Implement monitoring for Kerberos-related attacks
9. **Regular Assessment**: Conduct regular Kerberos security assessments
10. **Educate Teams**: Educate administrators on Kerberos security best practices

## Summary

Kerberos attack methodologies provide comprehensive analysis of Kerberos protocol vulnerabilities in Active Directory environments. The combination of Kerberoasting, AS-REP roasting, delegation analysis, and ticket analysis enables identification of security weaknesses while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.