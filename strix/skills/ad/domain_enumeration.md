---
name: ad-domain-enumeration
description: Active Directory domain enumeration using BloodHound/SharpHound integration logic, LDAP queries, and privilege escalation path mapping
---

# Active Directory Domain Enumeration

This skill provides comprehensive methodologies for enumerating Active Directory environments, mapping trust relationships, identifying privilege escalation paths, and assessing domain security posture.

## Core Concepts

### Domain Enumeration Strategies
- **LDAP Enumeration**: Query AD for users, groups, computers, and GPOs
- **BloodHound Integration**: Map attack paths and privilege escalation opportunities
- **Trust Relationship Analysis**: Identify cross-domain and forest trusts
- **ACL Analysis**: Examine access control lists for misconfigurations
- **Kerberos Ticket Analysis**: Identify delegation and service account weaknesses

### Security Boundaries
- **Domain Admin vs Enterprise Admin**: Understand privilege boundaries
- **Forest Trust Limits**: Respect inter-domain trust restrictions
- **Read-Only Operations**: Prioritize non-destructive enumeration
- **Local Lab Only**: These techniques are restricted to authorized local lab environments

## Tool Command Wrappers

### LDAP Enumeration Commands
```python
class LDAPEumerator:
    """LDAP-based AD enumeration tool wrapper."""
    
    def __init__(self, domain_controller: str, credentials: dict):
        self.dc = domain_controller
        self.creds = credentials
        self.base_dn = f"DC={','.join(domain_controller.split('.')[1:])}"
    
    def enumerate_users(self) -> list[dict]:
        """Enumerate all domain users with key attributes."""
        ldap_filter = "(objectClass=user)"
        attributes = ["sAMAccountName", "userPrincipalName", "distinguishedName", 
                     "lastLogon", "pwdLastSet", "memberOf", "adminCount"]
        
        results = self._ldap_search(ldap_filter, attributes)
        return self._process_user_results(results)
    
    def enumerate_groups(self) -> list[dict]:
        """Enumerate all domain groups and memberships."""
        ldap_filter = "(objectClass=group)"
        attributes = ["sAMAccountName", "distinguishedName", "memberOf", 
                     "groupType", "description"]
        
        results = self._ldap_search(ldap_filter, attributes)
        return self._process_group_results(results)
    
    def enumerate_computers(self) -> list[dict]:
        """Enumerate all domain computers and OS information."""
        ldap_filter = "(objectClass=computer)"
        attributes = ["sAMAccountName", "distinguishedName", "operatingSystem",
                     "operatingSystemVersion", "lastLogon", "pwdLastSet"]
        
        results = self._ldap_search(ldap_filter, attributes)
        return self._process_computer_results(results)
    
    def enumerate_gpos(self) -> list[dict]:
        """Enumerate Group Policy Objects and their scope."""
        ldap_filter = "(objectCategory=groupPolicyContainer)"
        attributes = ["displayName", "gPCFileSysPath", "versionNumber", 
                     "gPCFunctionalityVersion"]
        
        results = self._ldap_search(ldap_filter, attributes)
        return self._process_gpo_results(results)
    
    def check_password_policy(self) -> dict:
        """Analyze domain password policy."""
        ldap_filter = "(objectClass=domainDNS)"
        attributes = ["minPwdLength", "maxPwdAge", "minPwdAge", "pwdProperties",
                     "lockoutThreshold", "lockoutDuration", "lockoutObservationWindow"]
        
        results = self._ldap_search(ldap_filter, attributes)
        return self._analyze_password_policy(results)
    
    def _ldap_search(self, ldap_filter: str, attributes: list[str]) -> list[dict]:
        """Execute LDAP search with safety checks."""
        # Safety: Limit search scope and timeout
        search_controls = {
            "size_limit": 10000,  # Prevent excessive results
            "time_limit": 300,    # 5 minute timeout
            "scope": "subtree"
        }
        
        try:
            results = self._execute_ldap_search(ldap_filter, attributes, search_controls)
            return results
        except Exception as e:
            return {"error": str(e), "safety_violation": "LDAP search failed"}
    
    def _process_user_results(self, results: list) -> list[dict]:
        """Process user enumeration results for security analysis."""
        users = []
        for user in results:
            security_data = {
                "username": user.get("sAMAccountName"),
                "upn": user.get("userPrincipalName"),
                "dn": user.get("distinguishedName"),
                "is_admin": user.get("adminCount") == "1",
                "last_logon": self._convert_ad_timestamp(user.get("lastLogon")),
                "password_last_set": self._convert_ad_timestamp(user.get("pwdLastSet")),
                "groups": user.get("memberOf", []),
                "security_flags": self._identify_user_security_flags(user)
            }
            users.append(security_data)
        return users
```

### BloodHound/SharpHound Integration
```python
class BloodHoundAnalyzer:
    """BloodHound integration for attack path analysis."""
    
    def __init__(self, data_collector: LDAPEumerator):
        self.collector = data_collector
        self.graph_data = {}
    
    def collect_bloodhound_data(self) -> dict:
        """Collect data in BloodHound format."""
        # Safety: Collect only metadata, not sensitive credential data
        data = {
            "users": self._sanitize_user_data(self.collector.enumerate_users()),
            "groups": self._sanitize_group_data(self.collector.enumerate_groups()),
            "computers": self._sanitize_computer_data(self.collector.enumerate_computers()),
            "gpos": self._sanitize_gpo_data(self.collector.enumerate_gpos()),
            "relationships": self._map_relationships()
        }
        return data
    
    def identify_privilege_escalation_paths(self) -> list[dict]:
        """Identify potential privilege escalation paths."""
        paths = []
        
        # Analyze for common AD misconfigurations
        paths.extend(self._check_unconstrained_delegation())
        paths.extend(self._check_resource_based_constrained_delegation())
        paths.extend(self._check_asrep_roastable_users())
        paths.extend(self._check_kerberoastable_users())
        paths.extend(self._check_dcsync_permissions())
        paths.extend(self._check_ldaps_credentials())
        
        return paths
    
    def _check_unconstrained_delegation(self) -> list[dict]:
        """Identify accounts with unconstrained delegation."""
        vulnerable_accounts = []
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        results = self.collector._ldap_search(ldap_filter, ["sAMAccountName", "distinguishedName"])
        
        for account in results:
            vulnerable_accounts.append({
                "type": "unconstrained_delegation",
                "account": account.get("sAMAccountName"),
                "severity": "high",
                "description": "Account with unconstrained delegation can be used for privilege escalation",
                "mitigation": "Constrain delegation or remove unconstrained delegation flag"
            })
        
        return vulnerable_accounts
    
    def _check_dcsync_permissions(self) -> list[dict]:
        """Identify accounts with DCSync permissions."""
        vulnerable_accounts = []
        
        # Check for WriteDACL on domain object
        ldap_filter = "(objectClass=domainDNS)"
        results = self.collector._ldap_search(ldap_filter, ["distinguishedName"])
        
        if results:
            domain_dn = results[0].get("distinguishedName")
            acl_results = self.collector._get_acl(domain_dn)
            
            for ace in acl_results:
                if self._has_dcsync_permission(ace):
                    vulnerable_accounts.append({
                        "type": "dcsync_permission",
                        "account": ace.get("trustee"),
                        "severity": "critical",
                        "description": "Account has DCSync permissions to replicate domain secrets",
                        "mitigation": "Remove unnecessary replication permissions"
                    })
        
        return vulnerable_accounts
```

### Kerberos Enumeration
```python
class KerberosEnumerator:
    """Kerberos-specific enumeration and vulnerability analysis."""
    
    def __init__(self, domain_controller: str, domain: str):
        self.dc = domain_controller
        self.domain = domain
    
    def identify_kerberoastable_users(self) -> list[dict]:
        """Identify service accounts vulnerable to Kerberoasting."""
        kerberoastable = []
        
        # Find SPNs (Service Principal Names)
        ldap_filter = "(servicePrincipalName=*)"
        attributes = ["sAMAccountName", "servicePrincipalName", "pwdLastSet", 
                     "userAccountControl", "distinguishedName"]
        
        results = self._ldap_search(ldap_filter, attributes)
        
        for user in results:
            if self._is_kerberoastable(user):
                kerberoastable.append({
                    "username": user.get("sAMAccountName"),
                    "spns": user.get("servicePrincipalName"),
                    "password_last_set": self._convert_ad_timestamp(user.get("pwdLastSet")),
                    "account_disabled": self._is_account_disabled(user),
                    "severity": "medium",
                    "remediation": "Use strong passwords, rotate regularly, monitor for ticket requests"
                })
        
        return kerberoastable
    
    def identify_asrep_roastable_users(self) -> list[dict]:
        """Identify accounts vulnerable to AS-REP roasting."""
        asrep_roastable = []
        
        # Find accounts with Kerberos pre-auth disabled
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=4194304)"
        attributes = ["sAMAccountName", "distinguishedName", "userAccountControl"]
        
        results = self._ldap_search(ldap_filter, attributes)
        
        for user in results:
            asrep_roastable.append({
                "username": user.get("sAMAccountName"),
                "dn": user.get("distinguishedName"),
                "severity": "high",
                "description": "Account has Kerberos pre-authentication disabled (AS-REP roastable)",
                "remediation": "Enable Kerberos pre-authentication unless required"
            })
        
        return asrep_roastable
    
    def request_service_ticket(self, spn: str) -> dict:
        """Request a Kerberos service ticket for analysis (safe, read-only)."""
        try:
            # Safety: Only request ticket metadata, not extract credentials
            ticket_info = self._get_ticket_metadata(spn)
            return {
                "spn": spn,
                "ticket_type": ticket_info.get("etype"),
                "timestamp": ticket_info.get("timestamp"),
                "size": ticket_info.get("size"),
                "safety_check": "read_only_metadata_only"
            }
        except Exception as e:
            return {"error": str(e), "safety_violation": "Ticket request failed"}
```

### SMB Enumeration
```python
class SMBEnumerator:
    """SMB enumeration for Windows domain environment analysis."""
    
    def __init__(self, target_network: str):
        self.network = target_network
    
    def enumerate_smb_shares(self, target_ip: str) -> list[dict]:
        """Enumerate SMB shares on target (read-only)."""
        shares = []
        
        try:
            # Safety: Only enumerate share names and permissions, not access contents
            share_list = self._list_shares(target_ip)
            
            for share in share_list:
                share_info = {
                    "name": share.get("name"),
                    "type": share.get("type"),
                    "remark": share.get("remark"),
                    "is_anonymous": self._is_anonymous_access(share),
                    "permissions": self._get_share_permissions(share.get("name")),
                    "security_assessment": self._assess_share_security(share)
                }
                shares.append(share_info)
            
            return shares
        except Exception as e:
            return [{"error": str(e), "safety_violation": "SMB enumeration failed"}]
    
    def check_smb_signing(self, target_ip: str) -> dict:
        """Check SMB signing requirements."""
        signing_info = {
            "target": target_ip,
            "signing_required": self._check_signing_required(target_ip),
            "signing_enforced": self._check_signing_enforced(target_ip),
            "smb_version": self._get_smb_version(target_ip),
            "security_recommendation": self._get_signing_recommendation(target_ip)
        }
        return signing_info
```

## Safe Validation Rules

### Authorization Requirements
```python
class ADSafetyValidator:
    """Safety validation for AD enumeration operations."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate AD operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "AD enumeration only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "ldap_enumeration": self._validate_ldap_operation,
            "kerberos_analysis": self._validate_kerberos_operation,
            "smb_enumeration": self._validate_smb_operation,
            "bloodhound_analysis": self._validate_bloodhound_operation
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_ldap_operation(self, target: str) -> tuple[bool, str]:
        """Validate LDAP enumeration operations."""
        return True, "LDAP enumeration allowed in local lab mode"
    
    def _validate_kerberos_operation(self, target: str) -> tuple[bool, str]:
        """Validate Kerberos analysis operations."""
        # Safety: Only allow read-only Kerberos operations
        return True, "Read-only Kerberos analysis allowed"
    
    def _validate_smb_operation(self, target: str) -> tuple[bool, str]:
        """Validate SMB enumeration operations."""
        # Safety: Only allow share enumeration, not content access
        return True, "Share enumeration allowed in local lab mode"
    
    def _validate_bloodhound_operation(self, target: str) -> tuple[bool, str]:
        """Validate BloodHound data collection."""
        # Safety: Only collect metadata, not credential data
        return True, "Metadata-only BloodHound collection allowed"
```

## Enumeration Methodology

### Phase 1: Domain Reconnaissance
1. **Domain Controller Identification**: Identify all domain controllers
2. **Domain Trust Mapping**: Map intra-forest and cross-forest trusts
3. **User Enumeration**: Enumerate all users and group memberships
4. **Computer Enumeration**: Identify all domain-joined computers
5. **GPO Analysis**: Analyze Group Policy Objects for security settings

### Phase 2: Privilege Escalation Analysis
1. **BloodHound Data Collection**: Collect data for attack path analysis
2. **Kerberos Vulnerability Assessment**: Identify Kerberoastable and AS-REP roastable accounts
3. **Delegation Analysis**: Identify unconstrained and constrained delegation
4. **ACL Analysis**: Examine access control lists for misconfigurations
5. **DCSync Permission Check**: Identify accounts with replication permissions

### Phase 3: Lateral Movement Assessment
1. **SMB Share Enumeration**: Identify accessible shares and permissions
2. **RPC Service Analysis**: Identify vulnerable RPC services
3. **WinRM Configuration**: Check WinRM configuration and access
4. **WMI Access**: Assess WMI access permissions
5. **Remote Desktop**: Check RDP configuration and access

### Phase 4: Security Posture Assessment
1. **Password Policy Analysis**: Analyze domain password policies
2. **Account Policy Assessment**: Review account lockout and kerberos policies
3. **Audit Policy Review**: Assess audit and logging configuration
4. **Security Baseline**: Compare against security baselines
5. **Remediation Recommendations**: Provide prioritized remediation guidance

## Advanced Techniques

### Unconstrained Delegation Abuse
```python
class DelegationAnalyzer:
    """Analyze delegation configurations for security issues."""
    
    def identify_unconstrained_delegation_targets(self) -> list[dict]:
        """Identify computers/accounts with unconstrained delegation."""
        targets = []
        
        ldap_filter = "(userAccountControl:1.2.840.113556.1.4.803:=524288)"
        results = self._ldap_search(ldap_filter, ["sAMAccountName", "objectClass"])
        
        for result in results:
            if result.get("objectClass") == "computer":
                targets.append({
                    "type": "computer",
                    "name": result.get("sAMAccountName"),
                    "severity": "high",
                    "attack_vector": "Service ticket abuse for TGT delegation"
                })
            else:
                targets.append({
                    "type": "user",
                    "name": result.get("sAMAccountName"),
                    "severity": "medium",
                    "attack_vector": "Account delegation abuse"
                })
        
        return targets
```

### Resource-Based Constrained Delegation
```python
class RBCDAnalyzer:
    """Analyze resource-based constrained delegation configurations."""
    
    def identify_rbcd_misconfigurations(self) -> list[dict]:
        """Identify misconfigured RBCD settings."""
        misconfigurations = []
        
        # Check for accounts that can write msDS-AllowedToActOnBehalfOfOtherIdentity
        ldap_filter = "(objectClass=computer)"
        results = self._ldap_search(ldap_filter, ["sAMAccountName", "distinguishedName"])
        
        for computer in results:
            if self._has_writable_rbcd_attribute(computer):
                misconfigurations.append({
                    "computer": computer.get("sAMAccountName"),
                    "severity": "high",
                    "description": "Computer has writable RBCD attribute",
                    "remediation": "Restrict write permissions on msDS-AllowedToActOnBehalfOfOtherIdentity"
                })
        
        return misconfigurations
```

## Reporting and Findings

### Security Assessment Report
```python
class ADSecurityReporter:
    """Generate comprehensive AD security assessment reports."""
    
    def generate_domain_report(self, enumeration_data: dict) -> dict:
        """Generate domain security assessment report."""
        report = {
            "executive_summary": self._generate_executive_summary(enumeration_data),
            "domain_overview": self._generate_domain_overview(enumeration_data),
            "privilege_escalation_paths": self._generate_pe_analysis(enumeration_data),
            "kerberos_vulnerabilities": self._generate_kerberos_analysis(enumeration_data),
            "delegation_issues": self._generate_delegation_analysis(enumeration_data),
            "acl_misconfigurations": self._generate_acl_analysis(enumeration_data),
            "trust_relationships": self._generate_trust_analysis(enumeration_data),
            "remediation_roadmap": self._generate_remediation_roadmap(enumeration_data)
        }
        return report
    
    def _generate_executive_summary(self, data: dict) -> dict:
        """Generate executive summary of findings."""
        total_issues = len(data.get("vulnerabilities", []))
        critical_issues = len([v for v in data.get("vulnerabilities", []) if v.get("severity") == "critical"])
        
        return {
            "total_vulnerabilities": total_issues,
            "critical_vulnerabilities": critical_issues,
            "risk_score": self._calculate_risk_score(data),
            "security_posture": self._assess_security_posture(data),
            "key_findings": self._extract_key_findings(data)
        }
```

## Safety and Compliance

### Operational Security
- **Read-Only Operations**: All enumeration operations are read-only
- **Credential Protection**: No credential harvesting or extraction
- **Audit Trail**: All operations logged for compliance
- **Scope Limitation**: Strictly limited to authorized local lab environments
- **Rate Limiting**: Operations rate-limited to prevent disruption

### Ethical Guidelines
- **Authorization Only**: Only test authorized domain environments
- **Minimal Impact**: Use techniques that minimize operational impact
- **No Credential Extraction**: Focus on enumeration, not credential compromise
- **Respect Privacy**: Do not access user data beyond security assessment needs
- **Disclosure**: Follow responsible disclosure for critical findings

## Pro Tips

1. **Start with LDAP**: Begin with LDAP enumeration before more complex techniques
2. **Use BloodHound**: Leverage BloodHound for comprehensive attack path analysis
3. **Focus on High-Value Targets**: Prioritize Domain Admins and high-privilege groups
4. **Check Delegation**: Delegation misconfigurations are common attack vectors
5. **Analyze ACLs**: ACL misconfigurations often provide privilege escalation paths
6. **Monitor Kerberos**: Kerberos vulnerabilities are frequently overlooked
7. **Map Trusts**: Trust relationships can provide lateral movement paths
8. **Audit Policies**: Weak audit policies can hide security issues
9. **Document Everything**: Maintain detailed documentation for findings
10. **Validate Findings**: Always validate findings with multiple techniques

## Summary

Active Directory domain enumeration provides comprehensive security assessment of Windows domain environments. The combination of LDAP enumeration, BloodHound analysis, Kerberos vulnerability assessment, and SMB enumeration enables identification of privilege escalation paths and security misconfigurations while maintaining strict safety boundaries for authorized local lab testing.