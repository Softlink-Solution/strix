---
name: cloud-azure-security
description: Azure cloud security posture assessment including Blob storage security, Azure AD privilege analysis, network security group misconfigurations, and managed identity abuse
---

# Azure Cloud Security Posture Assessment

This skill provides comprehensive methodologies for assessing Azure cloud security posture, focusing on storage security, identity and access management, network security configurations, and potential managed identity abuse vectors.

## Core Concepts

### Azure Security Architecture
- **Storage Security**: Analyze Azure Blob storage configurations and access controls
- **Azure AD Analysis**: Assess Azure AD roles, users, and privilege assignments
- **Network Security**: Review security groups, NSGs, and VNet configurations
- **Managed Identity**: Identify potential managed identity abuse vectors
- **Azure Monitor Analysis**: Analyze audit logs for security events

### Attack Vectors
- **Public Blob Storage**: Exposed storage containers containing sensitive data
- **Over-Privileged Azure AD**: Excessive permissions assigned to Azure AD entities
- **NSG Misconfigurations**: Overly permissive network access rules
- **Managed Identity Abuse**: Excessive permissions assigned to managed identities
- **Missing Diagnostics**: Missing or misconfigured diagnostic logging

## Safety and Authorization

### Azure Analysis Safety Rules
```python
class AzureSafetyValidator:
    """Safety validation for Azure security analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate Azure analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "Azure analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "storage_analysis": self._validate_storage_analysis,
            "aad_analysis": self._validate_aad_analysis,
            "network_analysis": self._validate_network_analysis,
            "identity_analysis": self._validate_identity_analysis
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_storage_analysis(self, target: str) -> tuple[bool, str]:
        """Validate storage analysis operations."""
        # Safety: Only read-only storage operations
        return True, "Read-only storage analysis allowed in local lab mode"
    
    def _validate_aad_analysis(self, target: str) -> tuple[bool, str]:
        """Validate Azure AD analysis operations."""
        # Safety: Only read-only Azure AD operations
        return True, "Read-only Azure AD analysis allowed"
    
    def _validate_network_analysis(self, target: str) -> tuple[bool, str]:
        """Validate network analysis operations."""
        # Safety: Only read-only network analysis
        return True, "Read-only network analysis allowed"
    
    def _validate_identity_analysis(self, target: str) -> tuple[bool, str]:
        """Validate managed identity analysis operations."""
        # Safety: Only analysis, not exploitation
        return True, "Managed identity analysis allowed"
```

## Storage Security Analysis

### Azure Blob Storage Security Assessment
```python
class AzureStorageAnalyzer:
    """Analyze Azure Blob storage security configurations."""
    
    def __init__(self, azure_client):
        self.azure_client = azure_client
    
    def analyze_storage_security(self, account_name: str) -> dict:
        """Analyze security configuration of Azure storage account."""
        try:
            security_analysis = {
                "account_name": account_name,
                "public_access": self._check_public_access(account_name),
                "encryption": self._check_encryption(account_name),
                "network_rules": self._check_network_rules(account_name),
                "containers": self._analyze_containers(account_name),
                "security_recommendations": self._generate_storage_recommendations(account_name)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Storage analysis failed"}
    
    def _check_public_access(self, account_name: str) -> dict:
        """Check if storage account allows public access."""
        try:
            account_properties = self.azure_client.storage_accounts.get_properties(
                resource_group_name=self._get_resource_group(account_name),
                account_name=account_name
            )
            
            allow_blob_public_access = account_properties.allow_blob_public_access
            
            return {
                "allows_public_access": allow_blob_public_access,
                "severity": "high" if allow_blob_public_access else "info",
                "description": "Storage account allows public blob access" if allow_blob_public_access else "Storage account does not allow public blob access",
                "recommendation": "Disable public blob access and review container-level permissions" if allow_blob_public_access else "Good security posture"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_containers(self, account_name: str) -> list[dict]:
        """Analyze individual containers for security issues."""
        containers = []
        
        try:
            blob_service = self.azure_client.blob_service_client(account_name)
            container_list = blob_service.list_containers()
            
            for container in container_list:
                container_analysis = {
                    "name": container.name,
                    "public_access": self._check_container_public_access(account_name, container.name),
                    "access_level": self._get_container_access_level(account_name, container.name),
                    "security_issues": self._identify_container_issues(account_name, container.name)
                }
                containers.append(container_analysis)
        except Exception as e:
            pass
        
        return containers
    
    def _check_container_public_access(self, account_name: str, container_name: str) -> dict:
        """Check if container allows public access."""
        try:
            blob_service = self.azure_client.blob_service_client(account_name)
            container_client = blob_service.get_container_client(container_name)
            
            container_properties = container_client.get_container_properties()
            public_access = container_properties.public_access
            
            is_public = public_access not in [None, 'Off']
            
            return {
                "is_public": is_public,
                "access_level": public_access,
                "severity": "critical" if is_public else "info",
                "description": f"Container has public access level: {public_access}" if is_public else "Container is private",
                "recommendation": "Set container access level to private" if is_public else "Good security posture"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _check_network_rules(self, account_name: str) -> dict:
        """Check network security rules for storage account."""
        try:
            account_properties = self.azure_client.storage_accounts.get_properties(
                resource_group_name=self._get_resource_group(account_name),
                account_name=account_name
            )
            
            network_rules = account_properties.network_rule_set
            
            return {
                "default_action": network_rules.default_action,
                "bypass": network_rules.bypass,
                "virtual_network_rules": len(network_rules.virtual_network_rules),
                "ip_rules": len(network_rules.ip_rules),
                "severity": "medium" if network_rules.default_action == 'Allow' else "info",
                "description": f"Network default action: {network_rules.default_action}",
                "recommendation": "Configure network rules to restrict access" if network_rules.default_action == 'Allow' else "Good network security posture"
            }
        except Exception as e:
            return {"error": str(e)}
```

## Azure AD Security Analysis

### Azure AD Role and User Assessment
```python
class AzureADAnalyzer:
    """Analyze Azure AD roles and users for security issues."""
    
    def __init__(self, azure_client):
        self.azure_client = azure_client
    
    def analyze_aad_posture(self) -> dict:
        """Analyze overall Azure AD security posture."""
        aad_analysis = {
            "users": self._analyze_aad_users(),
            "groups": self._analyze_aad_groups(),
            "roles": self._analyze_aad_roles(),
            "app_registrations": self._analyze_app_registrations(),
            "security_recommendations": self._generate_aad_recommendations()
        }
        return aad_analysis
    
    def _analyze_aad_users(self) -> list[dict]:
        """Analyze Azure AD users for security issues."""
        users = []
        
        try:
            user_list = self.azure_client.graph_client.users.list()
            
            for user in user_list:
                user_analysis = {
                    "user_id": user.id,
                    "display_name": user.display_name,
                    "user_principal_name": user.user_principal_name,
                    "account_enabled": user.account_enabled,
                    "role_assignments": self._get_user_role_assignments(user.id),
                    "mfa_enabled": self._check_mfa_status(user.id),
                    "security_issues": self._identify_user_issues(user)
                }
                users.append(user_analysis)
        except Exception as e:
            pass
        
        return users
    
    def _analyze_aad_roles(self) -> list[dict]:
        """Analyze Azure AD role assignments for security issues."""
        roles = []
        
        try:
            role_definitions = self.azure_client.graph_client.role_definitions.list()
            
            for role_def in role_definitions:
                role_analysis = {
                    "role_id": role_def.id,
                    "display_name": role_def.display_name,
                    "description": role_def.description,
                    "is_builtin": role_def.is_built_in,
                    "permissions": role_def.permissions,
                    "assignments": self._get_role_assignments(role_def.id),
                    "security_issues": self._identify_role_issues(role_def)
                }
                roles.append(role_analysis)
        except Exception as e:
            pass
        
        return roles
    
    def _analyze_app_registrations(self) -> list[dict]:
        """Analyze application registrations for security issues."""
        apps = []
        
        try:
            app_list = self.azure_client.graph_client.applications.list()
            
            for app in app_list:
                app_analysis = {
                    "app_id": app.app_id,
                    "display_name": app.display_name,
                    "required_permissions": self._analyze_app_permissions(app),
                    "key_credentials": len(app.key_credentials) if app.key_credentials else 0,
                    "password_credentials": len(app.password_credentials) if app.password_credentials else 0,
                    "reply_urls": app.reply_urls if app.reply_urls else [],
                    "security_issues": self._identify_app_issues(app)
                }
                apps.append(app_analysis)
        except Exception as e:
            pass
        
        return apps
    
    def _analyze_app_permissions(self, app) -> dict:
        """Analyze application permissions for excessive access."""
        permission_analysis = {
            "required_resource_access": [],
            "excessive_permissions": []
        }
        
        if app.required_resource_access:
            for resource_access in app.required_resource_access:
                resource_app_id = resource_access.resource_app_id
                permission_names = [perm.value for perm in resource_access.resource_access]
                
                permission_analysis["required_resource_access"].append({
                    "resource_app_id": resource_app_id,
                    "permissions": permission_names
                })
                
                # Check for excessive permissions
                high_risk_permissions = ['Directory.ReadWrite.All', 'User.ReadWrite.All', 'Group.ReadWrite.All']
                for perm in permission_names:
                    if perm in high_risk_permissions:
                        permission_analysis["excessive_permissions"].append({
                            "permission": perm,
                            "severity": "high",
                            "description": "Application has excessive directory access",
                            "recommendation": "Review and restrict application permissions"
                        })
        
        return permission_analysis
```

## Network Security Analysis

### Network Security Group Assessment
```python
class AzureNetworkAnalyzer:
    """Analyze Azure network security configurations."""
    
    def __init__(self, azure_client):
        self.azure_client = azure_client
    
    def analyze_network_security(self, resource_group: str = None) -> dict:
        """Analyze network security configurations."""
        network_analysis = {
            "network_security_groups": self._analyze_nsgs(resource_group),
            "virtual_networks": self._analyze_vnets(resource_group),
            "network_recommendations": self._generate_network_recommendations()
        }
        return network_analysis
    
    def _analyze_nsgs(self, resource_group: str = None) -> list[dict]:
        """Analyze network security groups for misconfigurations."""
        nsgs = []
        
        try:
            if resource_group:
                nsg_list = self.azure_client.network.network_security_groups.list(resource_group_name=resource_group)
            else:
                nsg_list = self.azure_client.network.network_security_groups.list_all()
            
            for nsg in nsg_list:
                nsg_analysis = {
                    "name": nsg.name,
                    "resource_group": nsg.resource_group,
                    "location": nsg.location,
                    "security_rules": self._analyze_nsg_rules(nsg.security_rules),
                    "security_issues": self._identify_nsg_issues(nsg)
                }
                nsgs.append(nsg_analysis)
        except Exception as e:
            pass
        
        return nsgs
    
    def _analyze_nsg_rules(self, security_rules) -> list[dict]:
        """Analyze NSG rules for security issues."""
        rule_analysis = []
        
        if security_rules:
            for rule in security_rules:
                if rule.access == 'Allow':
                    if rule.source_address_prefix == '*' or rule.source_address_prefix == '0.0.0.0/0':
                        rule_analysis.append({
                            "rule_name": rule.name,
                            "direction": rule.direction,
                            "protocol": rule.protocol,
                            "source_port": rule.source_port_range,
                            "destination_port": rule.destination_port_range,
                            "source_address": rule.source_address_prefix,
                            "severity": "high",
                            "description": f"Rule allows access from anywhere",
                            "recommendation": "Restrict source to specific IP ranges"
                        })
                    
                    # Check for sensitive ports
                    if rule.destination_port_range == '22' or rule.destination_port_range == '3389':
                        if rule.source_address_prefix == '*' or rule.source_address_prefix == '0.0.0.0/0':
                            rule_analysis.append({
                                "rule_name": rule.name,
                                "sensitive_port": rule.destination_port_range,
                                "severity": "high",
                                "description": f"Sensitive port {rule.destination_port_range} open to the world",
                                "recommendation": f"Restrict {rule.destination_port_range} access to specific IP ranges"
                            })
        
        return rule_analysis
    
    def _identify_nsg_issues(self, nsg) -> list[dict]:
        """Identify NSG security issues."""
        issues = []
        
        # Check for default allow rules
        if nsg.security_rules:
            for rule in nsg.security_rules:
                if rule.name == 'AllowVNetInBound' and rule.access == 'Allow':
                    # This is expected but worth noting
                    pass
                
                if rule.name == 'AllowAzureLoadBalancerInBound' and rule.access == 'Allow':
                    # This is expected for load balancer scenarios
                    pass
        
        return issues
```

## Managed Identity Analysis

### Managed Identity Abuse Detection
```python
class ManagedIdentityAnalyzer:
    """Analyze managed identity configurations for abuse potential."""
    
    def __init__(self, azure_client):
        self.azure_client = azure_client
    
    def analyze_managed_identities(self, resource_group: str = None) -> dict:
        """Analyze managed identity configurations."""
        identity_analysis = {
            "system_assigned_identities": self._analyze_system_identities(resource_group),
            "user_assigned_identities": self._analyze_user_identities(resource_group),
            "identity_recommendations": self._generate_identity_recommendations()
        }
        return identity_analysis
    
    def _analyze_system_identities(self, resource_group: str = None) -> list[dict]:
        """Analyze system-assigned managed identities."""
        identities = []
        
        try:
            # Get resources with system-assigned identities
            if resource_group:
                resources = self.azure_client.resources.list_by_resource_group(resource_group)
            else:
                resources = self.azure_client.resources.list()
            
            for resource in resources:
                if resource.identity and resource.identity.type == 'SystemAssigned':
                    identity_analysis = {
                        "resource_id": resource.id,
                        "resource_type": resource.type,
                        "resource_name": resource.name,
                        "principal_id": resource.identity.principal_id,
                        "role_assignments": self._get_identity_role_assignments(resource.identity.principal_id),
                        "security_issues": self._identify_identity_issues(resource.identity.principal_id)
                    }
                    identities.append(identity_analysis)
        except Exception as e:
            pass
        
        return identities
    
    def _get_identity_role_assignments(self, principal_id: str) -> list[dict]:
        """Get role assignments for managed identity."""
        assignments = []
        
        try:
            role_assignments = self.azure_client.graph_client.role_assignments.filter(
                f"principalId eq '{principal_id}'"
            )
            
            for assignment in role_assignments:
                role_def = self.azure_client.graph_client.role_definitions.get(
                    assignment.role_definition_id
                )
                
                assignments.append({
                    "role_name": role_def.display_name,
                    "role_id": role_def.id,
                    "assignment_scope": assignment.resource_scope
                })
        except Exception as e:
            pass
        
        return assignments
    
    def _identify_identity_issues(self, principal_id: str) -> list[dict]:
        """Identify security issues with managed identity."""
        issues = []
        
        role_assignments = self._get_identity_role_assignments(principal_id)
        
        for assignment in role_assignments:
            # Check for high-privilege roles
            high_privilege_roles = [
                'Owner', 'Contributor', 'User Access Administrator',
                'Role Based Access Control Administrator'
            ]
            
            if assignment['role_name'] in high_privilege_roles:
                issues.append({
                    "type": "excessive_privileges",
                    "role": assignment['role_name'],
                    "severity": "high",
                    "description": f"Managed identity has high-privilege role: {assignment['role_name']}",
                    "recommendation": "Use least privilege roles for managed identities"
                })
        
        return issues
```

## Analysis Methodology

### Phase 1: Azure Resource Discovery
1. **Storage Discovery**: Enumerate all storage accounts and containers
2. **Azure AD Discovery**: Identify all users, groups, and roles
3. **Network Discovery**: Map VNets, NSGs, and network configurations
4. **Identity Discovery**: Identify managed identities and their assignments
5. **Service Discovery**: Catalog other Azure services in use

### Phase 2: Security Configuration Analysis
1. **Storage Security**: Analyze storage account configurations and access controls
2. **Azure AD Security**: Assess Azure AD roles and permission assignments
3. **Network Security**: Review NSG rules and network configurations
4. **Identity Security**: Analyze managed identity permissions and assignments
5. **Service Security**: Review security configurations of other services

### Phase 3: Risk Assessment
1. **Vulnerability Scoring**: Score identified security issues
2. **Risk Prioritization**: Prioritize risks based on impact and likelihood
3. **Attack Path Analysis**: Map potential attack paths
4. **Compliance Assessment**: Assess compliance with security standards
5. **Remediation Planning**: Develop prioritized remediation plan

## Remediation Guidance

### Storage Security
- **Disable Public Access**: Disable public blob access at account and container level
- **Enable Encryption**: Ensure storage account encryption is enabled
- **Configure Network Rules**: Implement network rules to restrict access
- **Use Private Endpoints**: Use private endpoints for secure access
- **Enable Diagnostics**: Enable storage diagnostics and logging

### Azure AD Security
- **Least Privilege**: Apply least privilege principle to Azure AD roles
- **Enable MFA**: Enable multi-factor authentication for all users
- **Review App Permissions**: Review and restrict application permissions
- **Monitor Activity**: Monitor Azure AD sign-in logs and activity
- **Implement Conditional Access**: Implement conditional access policies

### Network Security
- **Restrict NSG Rules**: Restrict NSG rules to specific IP ranges
- **Use Application Gateway**: Use Application Gateway for web applications
- **Implement Bastion**: Use Azure Bastion for secure VM access
- **Enable DDoS Protection**: Enable DDoS protection for critical resources
- **Use Private Endpoints**: Use private endpoints for service access

### Managed Identity Security
- **Least Privilege**: Use least privilege roles for managed identities
- **Regular Audits**: Conduct regular audits of identity permissions
- **Monitor Usage**: Monitor managed identity usage patterns
- **Separate Identities**: Use separate identities for different purposes
- **Implement Logging**: Enable logging for identity-related activities

## Safety Compliance

### Operational Boundaries
- **Read-Only Operations**: All operations are read-only analysis
- **No Resource Modification**: No modification of cloud resources
- **Audit Trail**: All operations logged for compliance
- **Rate Limiting**: Operations rate-limited to prevent service disruption
- **Local Lab Only**: Strictly limited to authorized local lab environments

### Ethical Guidelines
- **Authorized Subscriptions**: Only analyze authorized Azure subscriptions
- **Minimal Impact**: Use techniques that minimize operational impact
- **No Data Exfiltration**: No extraction of sensitive cloud data
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Compliance**: Ensure compliance with relevant regulations

## Pro Tips

1. **Start with Azure AD**: Begin with Azure AD analysis as it's the foundation of Azure security
2. **Automate Scanning**: Use automated tools for comprehensive coverage
3. **Focus on Public Assets**: Prioritize analysis of publicly accessible resources
4. **Check Unused Resources**: Identify and remove unused security resources
5. **Review Sign-in Logs**: Analyze Azure AD sign-in logs for security events
6. **Test Network Access**: Test network access restrictions
7. **Document Everything**: Maintain detailed documentation of findings
8. **Regular Assessments**: Conduct regular security posture assessments
9. **Use Azure Policy**: Implement Azure Policy for continuous compliance
10. **Enable Microsoft Defender**: Enable Microsoft Defender for threat detection

## Summary

Azure cloud security posture assessment provides comprehensive analysis of cloud infrastructure security through storage security analysis, Azure AD privilege assessment, network security review, and managed identity analysis. The combination of automated scanning and manual analysis enables identification of security misconfigurations while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.