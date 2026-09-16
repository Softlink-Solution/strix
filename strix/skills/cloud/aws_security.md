---
name: cloud-aws-security
description: AWS cloud security posture assessment including S3 bucket security, IAM privilege analysis, security group misconfigurations, and metadata service abuse
---

# AWS Cloud Security Posture Assessment

This skill provides comprehensive methodologies for assessing AWS cloud security posture, focusing on storage security, identity and access management, network security configurations, and potential metadata service abuse vectors.

## Core Concepts

### AWS Security Architecture
- **S3 Security**: Analyze S3 bucket configurations and access controls
- **IAM Analysis**: Assess IAM roles, users, and privilege assignments
- **Network Security**: Review security groups, NACLs, and VPC configurations
- **Metadata Service**: Identify potential metadata service abuse vectors
- **CloudTrail Analysis**: Analyze audit logs for security events

### Attack Vectors
- **Public S3 Buckets**: Exposed S3 buckets containing sensitive data
- **Over-Privileged IAM**: Excessive permissions assigned to IAM entities
- **Security Group Misconfigurations**: Overly permissive network access rules
- **Metadata Service Abuse**: SSRF attacks via instance metadata service
- **CloudTrail Logging**: Missing or misconfigured audit logging

## Safety and Authorization

### Cloud Analysis Safety Rules
```python
class CloudSafetyValidator:
    """Safety validation for cloud security analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate cloud analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "Cloud analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "s3_analysis": self._validate_s3_analysis,
            "iam_analysis": self._validate_iam_analysis,
            "network_analysis": self._validate_network_analysis,
            "metadata_analysis": self._validate_metadata_analysis
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_s3_analysis(self, target: str) -> tuple[bool, str]:
        """Validate S3 analysis operations."""
        # Safety: Only read-only S3 operations
        return True, "Read-only S3 analysis allowed in local lab mode"
    
    def _validate_iam_analysis(self, target: str) -> tuple[bool, str]:
        """Validate IAM analysis operations."""
        # Safety: Only read-only IAM operations
        return True, "Read-only IAM analysis allowed"
    
    def _validate_network_analysis(self, target: str) -> tuple[bool, str]:
        """Validate network analysis operations."""
        # Safety: Only read-only network analysis
        return True, "Read-only network analysis allowed"
    
    def _validate_metadata_analysis(self, target: str) -> tuple[bool, str]:
        """Validate metadata service analysis operations."""
        # Safety: Only analysis, not exploitation
        return True, "Metadata service analysis allowed"
```

## S3 Security Analysis

### S3 Bucket Security Assessment
```python
class S3SecurityAnalyzer:
    """Analyze S3 bucket security configurations."""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def analyze_bucket_security(self, bucket_name: str) -> dict:
        """Analyze security configuration of S3 bucket."""
        try:
            security_analysis = {
                "bucket_name": bucket_name,
                "public_access": self._check_public_access(bucket_name),
                "encryption": self._check_encryption(bucket_name),
                "versioning": self._check_versioning(bucket_name),
                "logging": self._check_logging(bucket_name),
                "policy": self._analyze_bucket_policy(bucket_name),
                "acl": self._analyze_bucket_acl(bucket_name),
                "security_recommendations": self._generate_recommendations(bucket_name)
            }
            return security_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "S3 analysis failed"}
    
    def _check_public_access(self, bucket_name: str) -> dict:
        """Check if bucket is publicly accessible."""
        try:
            # Check public access block configuration
            public_access_block = self.aws_client.get_public_access_block(Bucket=bucket_name)
            
            public_access_config = {
                "block_public_acls": public_access_block.get('PublicAccessBlockConfiguration', {}).get('BlockPublicAcls', False),
                "block_public_policy": public_access_block.get('PublicAccessBlockConfiguration', {}).get('BlockPublicPolicy', False),
                "ignore_public_acls": public_access_block.get('PublicAccessBlockConfiguration', {}).get('IgnorePublicAcls', False),
                "restrict_public_buckets": public_access_block.get('PublicAccessBlockConfiguration', {}).get('RestrictPublicBuckets', False)
            }
            
            # Check bucket policy for public access
            policy = self._analyze_bucket_policy(bucket_name)
            
            is_public = not all(public_access_config.values()) or policy.get("has_public_access", False)
            
            return {
                "is_public": is_public,
                "public_access_config": public_access_config,
                "severity": "critical" if is_public else "info",
                "description": "Bucket is publicly accessible" if is_public else "Bucket is not publicly accessible",
                "recommendation": "Enable public access block and review bucket policy" if is_public else "Good security posture"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_bucket_policy(self, bucket_name: str) -> dict:
        """Analyze bucket policy for security issues."""
        try:
            policy = self.aws_client.get_bucket_policy(Bucket=bucket_name)
            policy_text = policy.get('Policy', '{}')
            policy_dict = json.loads(policy_text)
            
            security_issues = []
            has_public_access = False
            
            for statement in policy_dict.get('Statement', []):
                effect = statement.get('Effect', '')
                principal = statement.get('Principal', '')
                action = statement.get('Action', '')
                
                if effect == 'Allow' and (principal == '*' or principal.get('AWS') == '*'):
                    has_public_access = True
                    security_issues.append({
                        "type": "public_access",
                        "severity": "critical",
                        "description": "Bucket policy allows public access",
                        "recommendation": "Restrict principal to specific AWS accounts or IAM users"
                    })
                
                if isinstance(action, str) and 's3:*' in action:
                    security_issues.append({
                        "type": "excessive_permissions",
                        "severity": "high",
                        "description": "Policy grants excessive S3 permissions",
                        "recommendation": "Restrict actions to specific S3 operations"
                    })
            
            return {
                "has_policy": True,
                "has_public_access": has_public_access,
                "security_issues": security_issues,
                "policy_statements": len(policy_dict.get('Statement', []))
            }
        except Exception as e:
            return {"has_policy": False, "error": str(e)}
    
    def _check_encryption(self, bucket_name: str) -> dict:
        """Check bucket encryption configuration."""
        try:
            encryption = self.aws_client.get_bucket_encryption(Bucket=bucket_name)
            
            encryption_config = encryption.get('ServerSideEncryptionConfiguration', {})
            rules = encryption_config.get('Rules', [])
            
            if rules:
                algorithm = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                kms_key = rules[0].get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID', '')
                
                return {
                    "encrypted": True,
                    "algorithm": algorithm,
                    "kms_key": bool(kms_key),
                    "severity": "info",
                    "description": f"Bucket encrypted with {algorithm}",
                    "recommendation": "Consider using AWS KMS for enhanced key management"
                }
            else:
                return {
                    "encrypted": False,
                    "severity": "high",
                    "description": "Bucket does not have default encryption enabled",
                    "recommendation": "Enable default encryption for the bucket"
                }
        except Exception as e:
            return {"encrypted": False, "error": str(e)}
    
    def _check_versioning(self, bucket_name: str) -> dict:
        """Check bucket versioning configuration."""
        try:
            versioning = self.aws_client.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get('Status', 'Suspended')
            
            return {
                "enabled": status == 'Enabled',
                "severity": "medium" if status != 'Enabled' else "info",
                "description": f"Versioning is {status}",
                "recommendation": "Enable versioning for data protection" if status != 'Enabled' else "Good security posture"
            }
        except Exception as e:
            return {"error": str(e)}
```

## IAM Security Analysis

### IAM Role and User Assessment
```python
class IAMSecurityAnalyzer:
    """Analyze IAM roles and users for security issues."""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def analyze_iam_posture(self) -> dict:
        """Analyze overall IAM security posture."""
        iam_analysis = {
            "roles": self._analyze_iam_roles(),
            "users": self._analyze_iam_users(),
            "policies": self._analyze_iam_policies(),
            "groups": self._analyze_iam_groups(),
            "security_recommendations": self._generate_iam_recommendations()
        }
        return iam_analysis
    
    def _analyze_iam_roles(self) -> list[dict]:
        """Analyze IAM roles for security issues."""
        roles = []
        
        try:
            paginator = self.aws_client.get_paginator('list_roles')
            for page in paginator.paginate():
                for role in page['Roles']:
                    role_name = role['RoleName']
                    role_analysis = {
                        "role_name": role_name,
                        "arn": role['Arn'],
                        "create_date": role['CreateDate'],
                        "trust_policy": self._analyze_trust_policy(role_name),
                        "permissions": self._analyze_role_permissions(role_name),
                        "security_issues": self._identify_role_issues(role_name)
                    }
                    roles.append(role_analysis)
        except Exception as e:
            pass
        
        return roles
    
    def _analyze_trust_policy(self, role_name: str) -> dict:
        """Analyze role trust policy for security issues."""
        try:
            trust_policy = self.aws_client.get_role_policy(RoleName=role_name, PolicyName='trust-policy')
            policy_document = json.loads(trust_policy['PolicyDocument'])
            
            security_issues = []
            
            for statement in policy_document.get('Statement', []):
                principal = statement.get('Principal', {})
                effect = statement.get('Effect', '')
                
                if effect == 'Allow' and (principal == '*' or principal.get('AWS') == '*'):
                    security_issues.append({
                        "type": "wildcard_principal",
                        "severity": "critical",
                        "description": "Trust policy allows any AWS account to assume role",
                        "recommendation": "Restrict principal to specific AWS accounts"
                    })
            
            return {
                "has_wildcard_principal": len(security_issues) > 0,
                "security_issues": security_issues
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _analyze_role_permissions(self, role_name: str) -> dict:
        """Analyze role permissions for excessive access."""
        try:
            attached_policies = self.aws_client.list_attached_role_policies(RoleName=role_name)
            
            permission_analysis = {
                "attached_policies": len(attached_policies['AttachedPolicies']),
                "inline_policies": len(self.aws_client.list_role_policies(RoleName=role_name)['PolicyNames']),
                "permissions_boundary": self._check_permissions_boundary(role_name),
                "excessive_permissions": self._check_excessive_permissions(role_name)
            }
            
            return permission_analysis
        except Exception as e:
            return {"error": str(e)}
    
    def _check_excessive_permissions(self, role_name: str) -> list[dict]:
        """Check for excessive permissions in role."""
        excessive_perms = []
        
        try:
            # Check for administrator access
            attached_policies = self.aws_client.list_attached_role_policies(RoleName=role_name)
            for policy in attached_policies['AttachedPolicies']:
                if 'AdministratorAccess' in policy['PolicyName']:
                    excessive_perms.append({
                        "type": "administrator_access",
                        "severity": "high",
                        "description": "Role has AdministratorAccess policy attached",
                        "recommendation": "Remove AdministratorAccess and use least privilege"
                    })
            
            # Check for wildcard actions in inline policies
            inline_policies = self.aws_client.list_role_policies(RoleName=role_name)
            for policy_name in inline_policies['PolicyNames']:
                policy = self.aws_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                policy_doc = json.loads(policy['PolicyDocument'])
                
                for statement in policy_doc.get('Statement', []):
                    action = statement.get('Action', [])
                    if isinstance(action, str) and '*' in action:
                        excessive_perms.append({
                            "type": "wildcard_action",
                            "severity": "high",
                            "description": f"Inline policy {policy_name} contains wildcard actions",
                            "recommendation": "Restrict actions to specific AWS operations"
                        })
        except Exception as e:
            pass
        
        return excessive_perms
```

## Network Security Analysis

### Security Group Assessment
```python
class NetworkSecurityAnalyzer:
    """Analyze AWS network security configurations."""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def analyze_network_security(self, vpc_id: str = None) -> dict:
        """Analyze network security configurations."""
        network_analysis = {
            "security_groups": self._analyze_security_groups(vpc_id),
            "nacls": self._analyze_nacls(vpc_id),
            "vpc_config": self._analyze_vpc_configuration(vpc_id),
            "network_recommendations": self._generate_network_recommendations()
        }
        return network_analysis
    
    def _analyze_security_groups(self, vpc_id: str = None) -> list[dict]:
        """Analyze security groups for misconfigurations."""
        security_groups = []
        
        try:
            paginator = self.aws_client.get_paginator('describe_security_groups')
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    if vpc_id and sg['VpcId'] != vpc_id:
                        continue
                    
                    sg_analysis = {
                        "group_id": sg['GroupId'],
                        "group_name": sg['GroupName'],
                        "vpc_id": sg['VpcId'],
                        "inbound_rules": self._analyze_security_group_rules(sg['IpPermissions'], 'inbound'),
                        "outbound_rules": self._analyze_security_group_rules(sg['IpPermissionsEgress'], 'outbound'),
                        "security_issues": self._identify_sg_issues(sg)
                    }
                    security_groups.append(sg_analysis)
        except Exception as e:
            pass
        
        return security_groups
    
    def _analyze_security_group_rules(self, rules: list, direction: str) -> list[dict]:
        """Analyze security group rules for security issues."""
        rule_analysis = []
        
        for rule in rules:
            for ip_range in rule.get('IpRanges', []):
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    rule_analysis.append({
                        "direction": direction,
                        "protocol": rule.get('IpProtocol', ''),
                        "from_port": rule.get('FromPort', 'N/A'),
                        "to_port": rule.get('ToPort', 'N/A'),
                        "cidr": cidr,
                        "severity": "high",
                        "description": f"{direction} rule allows access from anywhere (0.0.0.0/0)",
                        "recommendation": "Restrict to specific IP ranges"
                    })
            
            for ipv6_range in rule.get('Ipv6Ranges', []):
                cidr = ipv6_range.get('CidrIpv6', '')
                if cidr == '::/0':
                    rule_analysis.append({
                        "direction": direction,
                        "protocol": rule.get('IpProtocol', ''),
                        "from_port": rule.get('FromPort', 'N/A'),
                        "to_port": rule.get('ToPort', 'N/A'),
                        "cidr": cidr,
                        "severity": "high",
                        "description": f"{direction} rule allows access from anywhere (::/0)",
                        "recommendation": "Restrict to specific IPv6 ranges"
                    })
        
        return rule_analysis
    
    def _identify_sg_issues(self, sg: dict) -> list[dict]:
        """Identify security group security issues."""
        issues = []
        
        # Check for open SSH (port 22)
        for rule in sg['IpPermissions']:
            if rule.get('FromPort') == 22 and rule.get('ToPort') == 22:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        issues.append({
                            "type": "open_ssh",
                            "severity": "high",
                            "description": "SSH (port 22) is open to the world",
                            "recommendation": "Restrict SSH access to specific IP ranges"
                        })
        
        # Check for open RDP (port 3389)
        for rule in sg['IpPermissions']:
            if rule.get('FromPort') == 3389 and rule.get('ToPort') == 3389:
                for ip_range in rule.get('IpRanges', []):
                    if ip_range.get('CidrIp') == '0.0.0.0/0':
                        issues.append({
                            "type": "open_rdp",
                            "severity": "high",
                            "description": "RDP (port 3389) is open to the world",
                            "recommendation": "Restrict RDP access to specific IP ranges"
                        })
        
        return issues
```

## Metadata Service Analysis

### Metadata Service Abuse Detection
```python
class MetadataServiceAnalyzer:
    """Analyze potential metadata service abuse vectors."""
    
    def __init__(self, aws_client):
        self.aws_client = aws_client
    
    def analyze_metadata_risks(self, instance_id: str = None) -> dict:
        """Analyze metadata service abuse risks."""
        metadata_analysis = {
            "instance_profile": self._analyze_instance_profile(instance_id),
            "iam_role": self._analyze_instance_iam_role(instance_id),
            "ssrf_vectors": self._identify_ssrf_vectors(instance_id),
            "credential_exposure": self._assess_credential_exposure(instance_id),
            "remediation_recommendations": self._generate_metadata_recommendations()
        }
        return metadata_analysis
    
    def _analyze_instance_profile(self, instance_id: str = None) -> dict:
        """Analyze instance profile for metadata service risks."""
        try:
            if instance_id:
                instance = self.aws_client.describe_instances(InstanceIds=[instance_id])
                instance_profile = instance['Reservations'][0]['Instances'][0].get('IamInstanceProfile', {})
                
                if instance_profile:
                    return {
                        "has_instance_profile": True,
                        "profile_name": instance_profile.get('Arn', ''),
                        "risk_level": "high",
                        "description": "Instance has IAM profile with potential metadata service access",
                        "recommendation": "Implement IMDSv2 and restrict IAM role permissions"
                    }
            
            return {
                "has_instance_profile": False,
                "risk_level": "low",
                "description": "No instance profile or instance not specified"
            }
        except Exception as e:
            return {"error": str(e)}
    
    def _identify_ssrf_vectors(self, instance_id: str = None) -> list[dict]:
        """Identify potential SSRF vectors for metadata service abuse."""
        ssrf_vectors = []
        
        # Check for common SSRF vulnerabilities in instance
        # This would typically involve analyzing the instance's software stack
        # For this analysis, we provide guidance on common vectors
        
        common_vectors = [
            {
                "vector": "Web application SSRF",
                "description": "Web applications that make HTTP requests based on user input",
                "severity": "high",
                "remediation": "Implement input validation and use IMDSv2"
            },
            {
                "vector": "External service callbacks",
                "description": "Services that make callbacks to user-provided URLs",
                "severity": "medium",
                "remediation": "Validate callback URLs and implement network restrictions"
            },
            {
                "vector": "Third-party integrations",
                "description": "Third-party services that might access metadata service",
                "severity": "medium",
                "remediation": "Review third-party access and implement network controls"
            }
        ]
        
        return common_vectors
    
    def _assess_credential_exposure(self, instance_id: str = None) -> dict:
        """Assess potential credential exposure via metadata service."""
        try:
            if instance_id:
                instance = self.aws_client.describe_instances(InstanceIds=[instance_id])
                iam_instance_profile = instance['Reservations'][0]['Instances'][0].get('IamInstanceProfile', {})
                
                if iam_instance_profile:
                    # Check if the instance has access to sensitive permissions
                    role_name = iam_instance_profile.get('Arn', '').split('/')[-1]
                    role_permissions = self._analyze_role_permissions(role_name)
                    
                    sensitive_permissions = [
                        's3:*', 'ec2:*', 'iam:*', 'lambda:*', 'dynamodb:*'
                    ]
                    
                    has_sensitive_perms = any(
                        perm in str(role_permissions) for perm in sensitive_permissions
                    )
                    
                    return {
                        "has_sensitive_permissions": has_sensitive_perms,
                        "risk_level": "high" if has_sensitive_perms else "medium",
                        "description": "Instance has access to sensitive AWS permissions",
                        "recommendation": "Implement IMDSv2 and use least privilege IAM roles"
                    }
            
            return {
                "has_sensitive_permissions": False,
                "risk_level": "low"
            }
        except Exception as e:
            return {"error": str(e)}
```

## Analysis Methodology

### Phase 1: Cloud Resource Discovery
1. **S3 Discovery**: Enumerate all S3 buckets in the account
2. **IAM Discovery**: Identify all IAM roles, users, and groups
3. **Network Discovery**: Map VPCs, security groups, and NACLs
4. **Instance Discovery**: Identify EC2 instances and their profiles
5. **Service Discovery**: Catalog other AWS services in use

### Phase 2: Security Configuration Analysis
1. **S3 Security**: Analyze bucket configurations and access controls
2. **IAM Security**: Assess IAM roles and permission assignments
3. **Network Security**: Review security group rules and network ACLs
4. **Instance Security**: Analyze instance profiles and metadata service access
5. **Service Security**: Review security configurations of other services

### Phase 3: Risk Assessment
1. **Vulnerability Scoring**: Score identified security issues
2. **Risk Prioritization**: Prioritize risks based on impact and likelihood
3. **Attack Path Analysis**: Map potential attack paths
4. **Compliance Assessment**: Assess compliance with security standards
5. **Remediation Planning**: Develop prioritized remediation plan

## Remediation Guidance

### S3 Security
- **Enable Encryption**: Enable default encryption for all buckets
- **Block Public Access**: Enable public access block at account and bucket level
- **Review Policies**: Review and restrict bucket policies
- **Enable Versioning**: Enable versioning for data protection
- **Implement Logging**: Enable S3 access logging and CloudTrail

### IAM Security
- **Least Privilege**: Apply least privilege principle to IAM roles
- **Remove Administrator Access**: Remove AdministratorAccess from production roles
- **Use Permissions Boundaries**: Implement permissions boundaries for roles
- **Enable MFA**: Enable MFA for IAM users with console access
- **Regular Audits**: Conduct regular IAM permission audits

### Network Security
- **Restrict Security Groups**: Restrict security group rules to specific IP ranges
- **Close Unnecessary Ports**: Close unnecessary ports in security groups
- **Use NACLs**: Implement network ACLs as additional layer of security
- **VPC Flow Logs**: Enable VPC flow logs for network monitoring
- **Implement Bastion Hosts**: Use bastion hosts for secure access

### Metadata Service Security
- **Enable IMDSv2**: Enable Instance Metadata Service Version 2
- **Restrict IAM Roles**: Use least privilege IAM roles for instances
- **Network Controls**: Implement network controls to restrict metadata access
- **Monitor Access**: Monitor metadata service access patterns
- **Application Security**: Implement application-level SSRF protections

## Safety Compliance

### Operational Boundaries
- **Read-Only Operations**: All operations are read-only analysis
- **No Resource Modification**: No modification of cloud resources
- **Audit Trail**: All operations logged for compliance
- **Rate Limiting**: Operations rate-limited to prevent service disruption
- **Local Lab Only**: Strictly limited to authorized local lab environments

### Ethical Guidelines
- **Authorized Accounts**: Only analyze authorized AWS accounts
- **Minimal Impact**: Use techniques that minimize operational impact
- **No Data Exfiltration**: No extraction of sensitive cloud data
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Compliance**: Ensure compliance with relevant regulations

## Pro Tips

1. **Start with IAM**: Begin with IAM analysis as it's the foundation of AWS security
2. **Automate Scanning**: Use automated tools for comprehensive coverage
3. **Focus on Public Assets**: Prioritize analysis of publicly accessible resources
3. **Check Unused Resources**: Identify and remove unused security resources
4. **Review CloudTrail**: Analyze CloudTrail logs for security events
5. **Test Metadata Access**: Test metadata service access restrictions
6. **Document Everything**: Maintain detailed documentation of findings
7. **Regular Assessments**: Conduct regular security posture assessments
8. **Use AWS Config**: Implement AWS Config for continuous monitoring
9. **Enable GuardDuty**: Enable AWS GuardDuty for threat detection
10. **Review Third-Party**: Review third-party tools and integrations for security

## Summary

AWS cloud security posture assessment provides comprehensive analysis of cloud infrastructure security through S3 security analysis, IAM privilege assessment, network security review, and metadata service analysis. The combination of automated scanning and manual analysis enables identification of security misconfigurations while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on vulnerability identification and remediation guidance.