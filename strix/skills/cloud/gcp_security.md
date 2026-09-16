---
name: cloud-gcp-security
description: GCP cloud security posture assessment including Cloud Storage security, IAM privilege analysis, VPC firewall misconfigurations, and service account abuse
---

# GCP Cloud Security Posture Assessment

This skill provides comprehensive methodologies for assessing Google Cloud Platform security posture, focusing on storage security, identity and access management, network security configurations, and potential service account abuse vectors.

## Core Concepts

### GCP Security Architecture
- **Storage Security**: Analyze Cloud Storage bucket configurations and access controls
- **IAM Analysis**: Assess IAM roles, users, and privilege assignments
- **Network Security**: Review VPC firewall rules and network configurations
- **Service Account**: Identify potential service account abuse vectors
- **Cloud Audit Logging**: Analyze audit logs for security events

### Attack Vectors
- **Public Cloud Storage**: Exposed storage buckets containing sensitive data
- **Over-Privileged IAM**: Excessive permissions assigned to IAM entities
- **Firewall Misconfigurations**: Overly permissive network access rules
- **Service Account Abuse**: Excessive permissions assigned to service accounts
- **Missing Audit Logs**: Missing or misconfigured audit logging

## Safety and Authorization

### GCP Analysis Safety Rules
```python
class GCPSafetyValidator:
    """Safety validation for GCP security analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate GCP analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "GCP analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "storage_analysis": self._validate_storage_analysis,
            "iam_analysis": self._validate_iam_analysis,
            "network_analysis": self._validate_network_analysis,
            "service_account_analysis": self._validate_service_account_analysis
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_storage_analysis(self, target: str) -> tuple[bool, str]:
        """Validate storage analysis operations."""
        # Safety: Only read-only storage operations
        return True, "Read-only storage analysis allowed in local lab mode"
    
    def _validate_iam_analysis(self, target: str) -> tuple[bool, str]:
        """Validate IAM analysis operations."""
        # Safety: Only read-only IAM operations
        return True, "Read-only IAM analysis allowed"
    
    def _validate_network_analysis(self, target: str) -> tuple[bool, str]:
        """Validate network analysis operations."""
        # Safety: Only read-only network analysis
        return True, "Read-only network analysis allowed"
    
    def _validate_service_account_analysis(self, target: str) -> tuple[bool, str]:
        """Validate service account analysis operations."""
        # Safety: Only analysis, not exploitation
        return True, "Service account analysis allowed"
```

## Storage Security Analysis

### Cloud Storage Security Assessment
```python
class GCPStorageAnalyzer:
    """Analyze Cloud Storage bucket security configurations."""
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
    
    def analyze_storage_security(self, bucket_name: str) -> dict:
        """Analyze security configuration of Cloud Storage bucket."""
        try:
            security_analysis = {
                "bucket_name": bucket_name,
                "public_access": self._check_public_access(bucket_name),
                "encryption": self._check_encryption(bucket_name),
                "iam_permissions": self._analyze_bucket_iam(bucket_name),
                "lifecycle_management": self._check_lifecycle(bucket_name),
                "logging": self._check_logging(bucket_name),
                "security_recommendations": self._generate_storage_recommendations(bucket_name)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Storage analysis failed"}
    
    def _check_public_access(self, bucket_name: str) -> dict:
        """Check if bucket is publicly accessible."""
        try:
            bucket = self.gcp_client.storage.bucket(bucket_name)
            iam_config = bucket.iam_configuration
            
            # Check if bucket is public
            if iam_config.public_access_prevention is None or not iam_config.public_access_prevention:
                # Check IAM policies for public access
                policy = bucket.get_iam_policy()
                
                public_access = False
                for binding in policy.bindings:
                    if binding.get('role') in ['roles/storage.objectViewer', 'roles/storage.viewer']:
                        for member in binding.get('members', []):
                            if member == 'allUsers' or member == 'allAuthenticatedUsers':
                                public_access = True
                                break
                
                return {
                    "is_public": public_access,
                    "public_access_prevention": iam_config.public_access_prevention,
                    "severity": "critical" if public_access else "info",
                    "description": "Bucket is publicly accessible" if public_access else "Bucket is not publicly accessible",
                    "recommendation": "Enable public access prevention and review IAM policies" if public_access else "Good security posture"
                }
            
            return {
                "is_public": False,
                "public_access_prevention": iam_config.public_access_prevention,
                "severity": "info",
                "description": "Public access prevention enabled",
                "recommendation": "Good security posture"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_bucket_iam(self, bucket_name: str) -> dict:
        """Analyze bucket IAM permissions for security issues."""
        try:
            bucket = self.gcp_client.storage.bucket(bucket_name)
            policy = bucket.get_iam_policy()
            
            security_issues = []
            
            for binding in policy.bindings:
                role = binding.get('role', '')
                members = binding.get('members', [])
                
                # Check for public access
                if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                    security_issues.append({
                        "type": "public_access",
                        "role": role,
                        "members": members,
                        "severity": "critical",
                        "description": f"Bucket grants {role} to public",
                        "recommendation": "Remove public access from IAM policy"
                    })
                
                # Check for excessive permissions
                if role in ['roles/storage.admin', 'roles/storage.objectAdmin']:
                    security_issues.append({
                        "type": "excessive_permissions",
                        "role": role,
                        "members": members,
                        "severity": "high",
                        "description": f"Bucket grants excessive role: {role}",
                        "recommendation": "Use more restrictive roles"
                    })
            
            return {
                "total_bindings": len(policy.bindings),
                "security_issues": security_issues
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_encryption(self, bucket_name: str) -> dict:
        """Check bucket encryption configuration."""
        try:
            bucket = self.gcp_client.storage.bucket(bucket_name)
            encryption_config = bucket.encryption
            
            if encryption_config and encryption_config.default_kms_key_name:
                return {
                    "encrypted": True,
                    "encryption_type": "customer_managed_key",
                    "kms_key": encryption_config.default_kms_key_name,
                    "severity": "info",
                    "description": "Bucket uses customer-managed encryption keys",
                    "recommendation": "Good security posture with CMEK"
                }
            elif encryption_config:
                return {
                    "encrypted": True,
                    "encryption_type": "google_managed",
                    "severity": "info",
                    "description": "Bucket uses Google-managed encryption",
                    "recommendation": "Consider CMEK for enhanced security"
                }
            else:
                return {
                    "encrypted": False,
                    "severity": "medium",
                    "description": "Bucket does not have default encryption enabled",
                    "recommendation": "Enable default encryption for the bucket"
                }
        except Exception as e:
            return {"error": str(e)}
```

## IAM Security Analysis

### IAM Role and User Assessment
```python
class GCP IAMAnalyzer:
    """Analyze GCP IAM roles and users for security issues."""
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
    
    def analyze_iam_posture(self, project_id: str) -> dict:
        """Analyze overall IAM security posture."""
        iam_analysis = {
            "service_accounts": self._analyze_service_accounts(project_id),
            "iam_bindings": self._analyze_iam_bindings(project_id),
            "custom_roles": self._analyze_custom_roles(project_id),
            "security_recommendations": self._generate_iam_recommendations()
        }
        return iam_analysis
    
    def _analyze_service_accounts(self, project_id: str) -> list[dict]:
        """Analyze service accounts for security issues."""
        service_accounts = []
        
        try:
            credentials = self.gcp_client.credentials
            service_accounts_client = self.gcp_client.iam.service_accounts(project_id)
            
            for service_account in service_accounts_client.list():
                account_analysis = {
                    "email": service_account.email,
                    "project_id": service_account.project_id,
                    "unique_id": service_account.unique_id,
                    "disabled": service_account.disabled,
                    "key_count": self._count_service_account_keys(project_id, service_account.email),
                    "permissions": self._analyze_service_account_permissions(project_id, service_account.email),
                    "security_issues": self._identify_service_account_issues(project_id, service_account.email)
                }
                service_accounts.append(account_analysis)
        except Exception as e:
            pass
        
        return service_accounts
    
    def _analyze_service_account_permissions(self, project_id: str, service_account_email: str) -> dict:
        """Analyze service account permissions."""
        try:
            resource_manager = self.gcp_client.cloud_resource_manager
            policy = resource_manager.projects().getIamPolicy(
                resource=project_id,
                body={}
            ).execute()
            
            account_permissions = []
            
            for binding in policy.get('bindings', []):
                for member in binding.get('members', []):
                    if member == f"serviceAccount:{service_account_email}":
                        account_permissions.append({
                            "role": binding.get('role'),
                            "resource": project_id
                        })
            
            return {
                "total_permissions": len(account_permissions),
                "permissions": account_permissions
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _identify_service_account_issues(self, project_id: str, service_account_email: str) -> list[dict]:
        """Identify security issues with service account."""
        issues = []
        
        permissions = self._analyze_service_account_permissions(project_id, service_account_email)
        
        # Check for high-privilege roles
        high_privilege_roles = [
            'roles/owner', 'roles/editor', 'roles/iam.securityAdmin',
            'roles/resourcemanager.projectIamAdmin'
        ]
        
        for perm in permissions.get('permissions', []):
            if perm['role'] in high_privilege_roles:
                issues.append({
                    "type": "excessive_privileges",
                    "role": perm['role'],
                    "severity": "high",
                    "description": f"Service account has high-privilege role: {perm['role']}",
                    "recommendation": "Use least privilege roles for service accounts"
                })
        
        return issues
    
    def _analyze_iam_bindings(self, project_id: str) -> list[dict]:
        """Analyze IAM bindings for security issues."""
        bindings_analysis = []
        
        try:
            resource_manager = self.gcp_client.cloud_resource_manager
            policy = resource_manager.projects().getIamPolicy(
                resource=project_id,
                body={}
            ).execute()
            
            for binding in policy.get('bindings', []):
                role = binding.get('role')
                members = binding.get('members', [])
                
                # Check for public access
                if 'allUsers' in members or 'allAuthenticatedUsers' in members:
                    bindings_analysis.append({
                        "role": role,
                        "members": members,
                        "severity": "critical",
                        "description": f"Role {role} granted to public",
                        "recommendation": "Remove public access from IAM bindings"
                    })
                
                # Check for excessive permissions
                if role in ['roles/owner', 'roles/editor']:
                    bindings_analysis.append({
                        "role": role,
                        "members": members,
                        "severity": "high",
                        "description": f"Project-level {role} bindings",
                        "recommendation": "Review and restrict high-privilege roles"
                    })
        except Exception as e:
            pass
        
        return bindings_analysis
```

## Network Security Analysis

### VPC Firewall Assessment
```python
class GCPNetworkAnalyzer:
    """Analyze GCP network security configurations."""
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
    
    def analyze_network_security(self, project_id: str) -> dict:
        """Analyze network security configurations."""
        network_analysis = {
            "firewall_rules": self._analyze_firewall_rules(project_id),
            "vpc_networks": self._analyze_vpc_networks(project_id),
            "network_recommendations": self._generate_network_recommendations()
        }
        return network_analysis
    
    def _analyze_firewall_rules(self, project_id: str) -> list[dict]:
        """Analyze VPC firewall rules for misconfigurations."""
        firewall_rules = []
        
        try:
            compute_client = self.gcp_client.compute
            rules_list = compute_client.firewalls().list(project=project_id).execute()
            
            for rule in rules_list.get('items', []):
                rule_analysis = {
                    "name": rule.get('name'),
                    "network": rule.get('network'),
                    "direction": rule.get('direction'),
                    "priority": rule.get('priority'),
                    "source_ranges": rule.get('sourceRanges', []),
                    "allowed": rule.get('allowed', []),
                    "denied": rule.get('denied', []),
                    "security_issues": self._identify_firewall_issues(rule)
                }
                firewall_rules.append(rule_analysis)
        except Exception as e:
            pass
        
        return firewall_rules
    
    def _identify_firewall_issues(self, rule: dict) -> list[dict]:
        """Identify firewall rule security issues."""
        issues = []
        
        source_ranges = rule.get('sourceRanges', [])
        allowed_ports = rule.get('allowed', [])
        
        # Check for allow all traffic
        if '0.0.0.0/0' in source_ranges:
            for allowed in allowed_ports:
                if allowed.get('IPProtocol') == 'tcp' and not allowed.get('ports'):
                    issues.append({
                        "type": "allow_all_traffic",
                        "severity": "high",
                        "description": "Rule allows all TCP traffic from anywhere",
                        "recommendation": "Restrict to specific IP ranges and ports"
                    })
        
        # Check for open SSH (port 22)
        if '0.0.0.0/0' in source_ranges:
            for allowed in allowed_ports:
                if allowed.get('IPProtocol') == 'tcp' and allowed.get('ports') == ['22']:
                    issues.append({
                        "type": "open_ssh",
                        "severity": "high",
                        "description": "SSH (port 22) is open to the world",
                        "recommendation": "Restrict SSH access to specific IP ranges"
                    })
        
        # Check for open RDP (port 3389)
        if '0.0.0.0/0' in source_ranges:
            for allowed in allowed_ports:
                if allowed.get('IPProtocol') == 'tcp' and allowed.get('ports') == ['3389']:
                    issues.append({
                        "type": "open_rdp",
                        "severity": "high",
                        "description": "RDP (port 3389) is open to the world",
                        "recommendation": "Restrict RDP access to specific IP ranges"
                    })
        
        return issues
    
    def _analyze_vpc_networks(self, project_id: str) -> list[dict]:
        """Analyze VPC network configurations."""
        vpc_networks = []
        
        try:
            compute_client = self.gcp_client.compute
            networks_list = compute_client.networks().list(project=project_id).execute()
            
            for network in networks_list.get('items', []):
                network_analysis = {
                    "name": network.get('name'),
                    "auto_create_subnetworks": network.get('autoCreateSubnetworks'),
                    "subnet_mode": network.get('x_gcloud_subnet_mode'),
                    "routing_config": network.get('routingConfig'),
                    "security_issues": self._identify_network_issues(network)
                }
                vpc_networks.append(network_analysis)
        except Exception as e:
            pass
        
        return vpc_networks
```

## Service Account Analysis

### Service Account Abuse Detection
```python
class GCPServiceAccountAnalyzer:
    """Analyze service account configurations for abuse potential."""
    
    def __init__(self, gcp_client):
        self.gcp_client = gcp_client
    
    def analyze_service_account_security(self, project_id: str) -> dict:
        """Analyze service account security configurations."""
        account_analysis = {
            "service_accounts": self._analyze_all_service_accounts(project_id),
            "key_management": self._analyze_key_management(project_id),
            "impersonation_risks": self._analyze_impersonation_risks(project_id),
            "account_recommendations": self._generate_account_recommendations()
        }
        return account_analysis
    
    def _analyze_all_service_accounts(self, project_id: str) -> list[dict]:
        """Analyze all service accounts in the project."""
        accounts = []
        
        try:
            credentials = self.gcp_client.credentials
            service_accounts_client = self.gcp_client.iam.service_accounts(project_id)
            
            for service_account in service_accounts_client.list():
                account_analysis = {
                    "email": service_account.email,
                    "display_name": service_account.display_name,
                    "disabled": service_account.disabled,
                    "key_count": self._count_service_account_keys(project_id, service_account.email),
                    "key_age": self._analyze_key_age(project_id, service_account.email),
                    "impersonation_policy": self._analyze_impersonation_policy(project_id, service_account.email),
                    "security_issues": self._identify_account_issues(project_id, service_account.email)
                }
                accounts.append(account_analysis)
        except Exception as e:
            pass
        
        return accounts
    
    def _count_service_account_keys(self, project_id: str, service_account_email: str) -> int:
        """Count service account keys."""
        try:
            credentials = self.gcp_client.credentials
            keys_client = self.gcp_client.iam.projects().serviceAccounts().keys()
            
            keys_list = keys_client.list(
                name=f"projects/{project_id}/serviceAccounts/{service_account_email}"
            ).execute()
            
            return len(keys_list.get('keys', []))
        except Exception as e:
            return 0
    
    def _analyze_key_age(self, project_id: str, service_account_email: str) -> dict:
        """Analyze service account key age."""
        try:
            credentials = self.gcp_client.credentials
            keys_client = self.gcp_client.iam.projects().serviceAccounts().keys()
            
            keys_list = keys_client.list(
                name=f"projects/{project_id}/serviceAccounts/{service_account_email}"
            ).execute()
            
            key_ages = []
            for key in keys_list.get('keys', []):
                if 'validAfterTime' in key:
                    valid_after = key['validAfterTime']
                    # Calculate age (simplified)
                    key_ages.append({
                        "key_id": key.get('name', '').split('/')[-1],
                        "valid_after": valid_after,
                        "age_days": self._calculate_age_days(valid_after)
                    })
            
            return {
                "total_keys": len(key_ages),
                "key_ages": key_ages,
                "old_keys": len([k for k in key_ages if k['age_days'] > 90])
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_impersonation_policy(self, project_id: str, service_account_email: str) -> dict:
        """Analyze service account impersonation policy."""
        try:
            credentials = self.gcp_client.credentials
            iam_client = self.gcp_client.iam
            
            policy = iam_client.getIamPolicy(
                resource=f"projects/{project_id}/serviceAccounts/{service_account_email}"
            ).execute()
            
            impersonation_bindings = []
            
            for binding in policy.get('bindings', []):
                if binding.get('role') == 'roles/iam.serviceAccountTokenCreator':
                    impersonation_bindings.append({
                        "members": binding.get('members', []),
                        "condition": binding.get('condition')
                    })
            
            return {
                "has_impersonation_policy": len(impersonation_bindings) > 0,
                "impersonation_bindings": impersonation_bindings
            }
        except Exception as e:
            return {"error": str(e)}
```

## Analysis Methodology

### Phase 1: GCP Resource Discovery
1. **Storage Discovery**: Enumerate all Cloud Storage buckets
2. **IAM Discovery**: Identify all service accounts and IAM bindings
3. **Network Discovery**: Map VPCs, subnets, and firewall rules
4. **Service Discovery**: Catalog other GCP services in use
5. **Project Discovery**: Identify all projects in the organization

### Phase 2: Security Configuration Analysis
1. **Storage Security**: Analyze bucket configurations and access controls
2. **IAM Security**: Assess service accounts and permission assignments
3. **Network Security**: Review firewall rules and VPC configurations
4. **Service Security**: Review security configurations of other services
5. **Organization Security**: Analyze organization-level security policies

### Phase 3: Risk Assessment
1. **Vulnerability Scoring**: Score identified security issues
2. **Risk Prioritization**: Prioritize risks based on impact and likelihood
3. **Attack Path Analysis**: Map potential attack paths
4. **Compliance Assessment**: Assess compliance with security standards
5. **Remediation Planning**: Develop prioritized remediation plan

## Remediation Guidance

### Storage Security
- **Disable Public Access**: Enable public access prevention
- **Configure IAM**: Restrict IAM policies to specific principals
- **Enable Encryption**: Enable customer-managed encryption keys
- **Implement Logging**: Enable access logging and Cloud Audit Logs
- **Use Uniform Access**: Use uniform bucket-level access

### IAM Security
- **Least Privilege**: Apply least privilege principle to service accounts
- **Key Management**: Regularly rotate service account keys
- **Disable Unused Accounts**: Disable unused service accounts
- **Monitor Usage**: Monitor service account usage patterns
- **Impersonation Policies**: Implement proper impersonation policies

### Network Security
- **Restrict Firewall Rules**: Restrict firewall rules to specific IP ranges
- **Use Private Google Access**: Use Private Google Access for VPCs
- **Implement VPC Service Controls**: Use VPC Service Controls for data protection
- **Enable Cloud Armor**: Enable Cloud Armor for external load balancers
- **Use Cloud NAT**: Use Cloud NAT for private instances

### Service Account Security
- **Least Privilege**: Use least privilege roles for service accounts
- **Key Rotation**: Regularly rotate service account keys
- **Key Management**: Implement proper key lifecycle management
- **Impersonation**: Use impersonation instead of keys when possible
- **Monitoring**: Enable monitoring for service account activities

## Safety Compliance

### Operational Boundaries
- **Read-Only Operations**: All operations are read-only analysis
- **No Resource Modification**: No modification of cloud resources
- **Audit Trail**: All operations logged for compliance
- **Rate Limiting**: Operations rate-limited to prevent service disruption
- **Local Lab Only**: Strictly limited to authorized local lab environments

### Ethical Guidelines
- **Authorized Projects**: Only analyze authorized GCP projects
- **Minimal Impact**: Use techniques that minimize operational impact
- **No Data Exfiltration**: No extraction of sensitive cloud data
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Compliance**: Ensure compliance with relevant regulations

## Pro Tips

1. **Start with IAM**: Begin with IAM analysis as it's the foundation of GCP security
2. **Automate Scanning**: Use automated tools for comprehensive coverage
3. **Focus on Public Assets**: Prioritize analysis of publicly accessible resources
4. **Check Service Accounts**: Service accounts are common attack vectors
5. **Review Firewall Rules**: Firewall rules are frequently misconfigured
6. **Analyze Key Age**: Old service account keys indicate security issues
7. **Document Everything**: Maintain detailed documentation of findings
8. **Regular Assessments**: Conduct regular security posture assessments
9. **Use Security Command Center**: Enable Security Command Center for threat detection
10. **Implement Organization Policies**: Implement organization-level security policies

## Summary

GCP cloud security posture assessment provides comprehensive analysis of cloud infrastructure security through storage security analysis, IAM privilege assessment, network security review, and service account analysis. The combination of automated scanning and manual analysis enables identification of security misconfigurations while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.