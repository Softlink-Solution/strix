---
name: dfir-log-analysis
description: DFIR and threat hunting log analysis playbooks for Windows Event Logs, Linux auth logs, web server access logs, and MITRE ATT&CK framework mapping
---

# DFIR and Threat Hunting Log Analysis

This skill provides comprehensive methodologies for digital forensics and incident response through log analysis, focusing on Windows Event Logs, Linux authentication logs, web server access logs, and MITRE ATT&CK framework mapping for threat hunting.

## Core Concepts

### DFIR Log Analysis Architecture
- **Windows Event Logs**: Analyze Windows Event Logs for security events
- **Linux Auth Logs**: Analyze Linux authentication and system logs
- **Web Server Logs**: Analyze web server access and error logs
- **MITRE ATT&CK Mapping**: Map log events to MITRE ATT&CK techniques
- **Threat Hunting**: Proactive threat detection through log analysis

### Attack Vectors
- **Privilege Escalation**: Techniques for gaining higher privileges
- **Lateral Movement**: Techniques for moving across systems
- **Credential Access**: Techniques for stealing credentials
- **Persistence**: Techniques for maintaining access
- **Defense Evasion**: Techniques for avoiding detection

## Safety and Authorization

### DFIR Analysis Safety Rules
```python
class DFIRSafetyValidator:
    """Safety validation for DFIR log analysis."""
    
    def __init__(self, governance_manager):
        self.governance = governance_manager
    
    def validate_operation(self, operation: str, target: str) -> tuple[bool, str]:
        """Validate DFIR analysis operation against safety rules."""
        
        # Check environment mode
        if not self.governance.is_local_lab:
            return False, "DFIR analysis only allowed in local_lab mode"
        
        # Check target authorization
        try:
            self.governance.check_target_authorization(target)
        except Exception as e:
            return False, f"Target not authorized: {e}"
        
        # Operation-specific safety checks
        safety_checks = {
            "windows_log_analysis": self._validate_windows_log_analysis,
            "linux_log_analysis": self._validate_linux_log_analysis,
            "web_log_analysis": self._validate_web_log_analysis,
            "threat_hunting": self._validate_threat_hunting
        }
        
        validator = safety_checks.get(operation, self._default_validator)
        return validator(target)
    
    def _validate_windows_log_analysis(self, target: str) -> tuple[bool, str]:
        """Validate Windows log analysis operations."""
        # Safety: Only read-only log analysis
        return True, "Read-only Windows log analysis allowed in local lab mode"
    
    def _validate_linux_log_analysis(self, target: str) -> tuple[bool, str]:
        """Validate Linux log analysis operations."""
        # Safety: Only read-only log analysis
        return True, "Read-only Linux log analysis allowed"
    
    def _validate_web_log_analysis(self, target: str) -> tuple[bool, str]:
        """Validate web log analysis operations."""
        # Safety: Only read-only log analysis
        return True, "Read-only web log analysis allowed"
    
    def _validate_threat_hunting(self, target: str) -> tuple[bool, str]:
        """Validate threat hunting operations."""
        # Safety: Only analysis, not exploitation
        return True, "Threat hunting analysis allowed"
```

## Windows Event Log Analysis

### Windows Security Event Analysis
```python
class WindowsLogAnalyzer:
    """Analyze Windows Event Logs for security events."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.mitre_mapping = self._load_mitre_mapping()
    
    def analyze_windows_logs(self) -> dict:
        """Analyze Windows Event Logs for security events."""
        try:
            log_analysis = {
                "log_path": self.log_path,
                "security_events": self._analyze_security_events(),
                "privilege_escalation": self._detect_privilege_escalation(),
                "lateral_movement": self._detect_lateral_movement(),
                "credential_access": self._detect_credential_access(),
                "persistence": self._detect_persistence(),
                "mitre_techniques": self._map_to_mitre_attack(),
                "threat_hunting_recommendations": self._generate_threat_hunting_recommendations()
            }
            return log_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Windows log analysis failed"}
    
    def _analyze_security_events(self) -> list[dict]:
        """Analyze security events in Windows Event Logs."""
        security_events = []
        
        # Critical Windows Security Event IDs
        critical_event_ids = {
            4624: "An account was successfully logged on",
            4625: "An account failed to log on",
            4627: "Group membership enumeration",
            4634: "An account was logged off",
            4648: "A logon was attempted using explicit credentials",
            4672: "Special privileges assigned to new logon",
            4674: "An operation was attempted on a privileged object",
            4688: "A member was added to a security-enabled group",
            4697: "SIDs were filtered",
            4706: "A new trust was created to a domain controller",
            4719: "System audit policy was changed",
            4720: "A user account was created",
            4722: "A user account was enabled",
            4723: "A user account password was changed",
            4724: "An attempt was made to reset an account's password",
            4728: "A member was added to a security-enabled global group",
            4732: "A member was added to a security-enabled local group",
            4738: "A member was removed from a security-enabled local group",
            4740: "A user account was changed",
            4756: "A user's account was added to a security-enabled global group",
            4768: "A member was added to a security-enabled directory group",
            4776: "A member was added to a security-enabled universal group",
            4780: "The ACL was set on accounts which are members of administrators groups",
            4798: "A user's local group membership was enumerated",
            4964: "Special groups have been assigned to a new logon",
            5140: "A network share object was accessed",
            5145: "A user has requested a type of access token"
        }
        
        # Analyze logs for critical events
        log_events = self._parse_windows_logs()
        
        for event in log_events:
            event_id = event.get('EventID')
            if event_id in critical_event_ids:
                security_events.append({
                    "event_id": event_id,
                    "timestamp": event.get('TimeCreated'),
                    "description": critical_event_ids[event_id],
                    "severity": self._assess_event_severity(event_id),
                    "mitre_technique": self._map_event_to_mitre(event_id),
                    "investigation_required": self._requires_investigation(event_id)
                })
        
        return security_events
    
    def _detect_privilege_escalation(self) -> list[dict]:
        """Detect privilege escalation attempts."""
        privilege_escalation_events = []
        
        # Privilege escalation indicators
        escalation_indicators = [
            4672,  # Special privileges assigned to new logon
            4673,  # A privileged service was called
            4674,  # An operation was attempted on a privileged object
            4688,  # A member was added to a security-enabled group
            4728,  # A member was added to a security-enabled global group
            4732,  # A member was added to a security-enabled local group
            4768,  # A member was added to a security-enabled directory group
            4776,  # A member was added to a security-enabled universal group
            4964   # Special groups have been assigned to a new logon
        ]
        
        log_events = self._parse_windows_logs()
        
        for event in log_events:
            event_id = event.get('EventID')
            if event_id in escalation_indicators:
                privilege_escalation_events.append({
                    "event_id": event_id,
                    "timestamp": event.get('TimeCreated'),
                    "user": event.get('SubjectUserName'),
                    "privilege": event.get('PrivilegeList'),
                    "group": event.get('GroupName'),
                    "mitre_technique": "T1068 - Privilege Escalation",
                    "severity": "high",
                    "description": "Potential privilege escalation detected"
                })
        
        return privilege_escalation_events
    
    def _detect_lateral_movement(self) -> list[dict]:
        """Detect lateral movement attempts."""
        lateral_movement_events = []
        
        # Lateral movement indicators
        movement_indicators = [
            4624,  # Remote logon
            4625,  # Failed remote logon
            4648,  # Explicit credential logon
            5140,  # Network share access
            5145   # Network share object access
        ]
        
        log_events = self._parse_windows_logs()
        
        for event in log_events:
            event_id = event.get('EventID')
            if event_id in movement_indicators:
                lateral_movement_events.append({
                    "event_id": event_id,
                    "timestamp": event.get('TimeCreated'),
                    "source_computer": event.get('WorkstationName'),
                    "target_computer": event.get('TargetComputerName'),
                    "user": event.get('SubjectUserName'),
                    "mitre_technique": "T1021 - Remote Services",
                    "severity": "medium",
                    "description": "Potential lateral movement detected"
                })
        
        return lateral_movement_events
    
    def _detect_credential_access(self) -> list[dict]:
        """Detect credential access attempts."""
        credential_access_events = []
        
        # Credential access indicators
        credential_indicators = [
            4624,  # Logon with credentials
            4625,  # Failed logon
            4648,  # Explicit credential logon
            4771,  # Kerberos pre-authentication failed
            4768,  # Kerberos TGT request
            4769,  # Kerberos TGS request
            4770   # Kerberos service ticket requested
        ]
        
        log_events = self._parse_windows_logs()
        
        for event in log_events:
            event_id = event.get('EventID')
            if event_id in credential_indicators:
                credential_access_events.append({
                    "event_id": event_id,
                    "timestamp": event.get('TimeCreated'),
                    "user": event.get('SubjectUserName'),
                    "service": event.get('ServiceName'),
                    "mitre_technique": "T1003 - OS Credential Dumping",
                    "severity": "high",
                    "description": "Potential credential access detected"
                })
        
        return credential_access_events
    
    def _detect_persistence(self) -> list[dict]:
        """Detect persistence mechanisms."""
        persistence_events = []
        
        # Persistence indicators
        persistence_indicators = [
            4688,  # Group membership changes
            4697,  # SID filtering
            4706,  # Trust creation
            4719,  # Audit policy changes
            4720,  # User account creation
            4722,  # User account enabled
            4723,  # Password change
            4724,  # Password reset
            4738,  # Group member removal
            4740,  # User account change
            4756,  # Global group membership
            4780,  # ACL changes on admin groups
            4964   # Special group assignment
        ]
        
        log_events = self._parse_windows_logs()
        
        for event in log_events:
            event_id = event.get('EventID')
            if event_id in persistence_indicators:
                persistence_events.append({
                    "event_id": event_id,
                    "timestamp": event.get('TimeCreated'),
                    "user": event.get('SubjectUserName'),
                    "account": event.get('TargetUserName'),
                    "mitre_technique": "T1547 - Boot or Logon Autostart Execution",
                    "severity": "medium",
                    "description": "Potential persistence mechanism detected"
                })
        
        return persistence_events
```

## Linux Authentication Log Analysis

### Linux Security Log Analysis
```python
class LinuxLogAnalyzer:
    """Analyze Linux authentication and system logs."""
    
    def __init__(self, log_path: str):
        self.log_path = log_path
        self.mitre_mapping = self._load_mitre_mapping()
    
    def analyze_linux_logs(self) -> dict:
        """Analyze Linux authentication and system logs."""
        try:
            log_analysis = {
                "log_path": self.log_path,
                "auth_events": self._analyze_auth_events(),
                "privilege_escalation": self._detect_linux_privilege_escalation(),
                "lateral_movement": self._detect_linux_lateral_movement(),
                "credential_access": self._detect_linux_credential_access(),
                "persistence": self._detect_linux_persistence(),
                "mitre_techniques": self._map_linux_to_mitre_attack(),
                "threat_hunting_recommendations": self._generate_linux_threat_hunting_recommendations()
            }
            return log_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Linux log analysis failed"}
    
    def _analyze_auth_events(self) -> list[dict]:
        """Analyze authentication events in Linux logs."""
        auth_events = []
        
        # Common Linux authentication log patterns
        auth_patterns = {
            r'accepted password': "Successful login",
            r'failed password': "Failed login attempt",
            r'invalid user': "Invalid user attempt",
            r'session opened': "Session started",
            r'session closed': "Session ended",
            r'pam_unix\(sshd:auth\): authentication failure': "SSH authentication failure",
            r'pam_unix\(sudo:auth\): conversation failed': "Sudo authentication failure",
            r'sudo:.*: TTY=.* ; PWD=.* ; USER=.* ; COMMAND=': "Sudo command execution"
        }
        
        log_entries = self._parse_linux_logs()
        
        for entry in log_entries:
            for pattern, description in auth_patterns.items():
                if re.search(pattern, entry, re.IGNORECASE):
                    auth_events.append({
                        "timestamp": self._extract_timestamp(entry),
                        "description": description,
                        "pattern": pattern,
                        "severity": self._assess_auth_severity(pattern),
                        "mitre_technique": self._map_auth_to_mitre(pattern),
                        "entry": entry
                    })
        
        return auth_events
    
    def _detect_linux_privilege_escalation(self) -> list[dict]:
        """Detect Linux privilege escalation attempts."""
        privilege_escalation_events = []
        
        escalation_patterns = [
            r'sudo:.*: COMMAND=': "Sudo command execution",
            r'su:.*:.*for .*': "Su command execution",
            r'polkit:.*authority.*': "PolicyKit privilege escalation",
            r'pkexec:.*': "pkexec privilege escalation",
            r'pam_unix\(sudo:auth\).*': "Sudo authentication",
            r'pam_unix\(su:auth\).*': "Su authentication"
        ]
        
        log_entries = self._parse_linux_logs()
        
        for entry in log_entries:
            for pattern in escalation_patterns:
                if re.search(pattern, entry, re.IGNORECASE):
                    privilege_escalation_events.append({
                        "timestamp": self._extract_timestamp(entry),
                        "description": pattern,
                        "user": self._extract_user(entry),
                        "command": self._extract_command(entry),
                        "mitre_technique": "T1068 - Privilege Escalation",
                        "severity": "high",
                        "entry": entry
                    })
        
        return privilege_escalation_events
    
    def _detect_linux_lateral_movement(self) -> list[dict]:
        """Detect Linux lateral movement attempts."""
        lateral_movement_events = []
        
        movement_patterns = [
            r'sshd.*accepted password': "SSH login",
            r'sshd.*failed password': "Failed SSH login",
            r'sshd.*invalid user': "Invalid SSH user",
            r'cron.*': "Cron job execution",
            r'systemd.*starting service': "Service start",
            r'systemctl.*start.*': "Service start via systemctl"
        ]
        
        log_entries = self._parse_linux_logs()
        
        for entry in log_entries:
            for pattern in movement_patterns:
                if re.search(pattern, entry, re.IGNORECASE):
                    lateral_movement_events.append({
                        "timestamp": self._extract_timestamp(entry),
                        "description": pattern,
                        "source": self._extract_source_ip(entry),
                        "user": self._extract_user(entry),
                        "mitre_technique": "T1021 - Remote Services",
                        "severity": "medium",
                        "entry": entry
                    })
        
        return lateral_movement_events
    
    def _detect_linux_credential_access(self) -> list[dict]:
        """Detect Linux credential access attempts."""
        credential_access_events = []
        
        credential_patterns = [
            r'sshd.*accepted password': "SSH credential usage",
            r'sshd.*failed password': "Failed credential attempt",
            r'su:.*:.*for .*': "Su credential usage",
            r'sudo:.*: COMMAND=': "Sudo credential usage",
            r'passwd:.*: changing password': "Password change",
            r'chage:.*: changing password': "Password change via chage"
        ]
        
        log_entries = self._parse_linux_logs()
        
        for entry in log_entries:
            for pattern in credential_patterns:
                if re.search(pattern, entry, re.IGNORECASE):
                    credential_access_events.append({
                        "timestamp": self._extract_timestamp(entry),
                        "description": pattern,
                        "user": self._extract_user(entry),
                        "mitre_technique": "T1003 - OS Credential Dumping",
                        "severity": "high",
                        "entry": entry
                    })
        
        return credential_access_events
```

## Web Server Log Analysis

### Web Server Access Log Analysis
```python
class WebLogAnalyzer:
    """Analyze web server access and error logs."""
    
    def __init__(self, access_log_path: str, error_log_path: str = None):
        self.access_log_path = access_log_path
        self.error_log_path = error_log_path
        self.mitre_mapping = self._load_mitre_mapping()
    
    def analyze_web_logs(self) -> dict:
        """Analyze web server access and error logs."""
        try:
            log_analysis = {
                "access_log_path": self.access_log_path,
                "error_log_path": self.error_log_path,
                "web_attacks": self._detect_web_attacks(),
                "sql_injection": self._detect_sql_injection(),
                "xss_attempts": self._detect_xss_attempts(),
                "path_traversal": self._detect_path_traversal(),
                "brute_force": self._detect_brute_force(),
                "mitre_techniques": self._map_web_to_mitre_attack(),
                "threat_hunting_recommendations": self._generate_web_threat_hunting_recommendations()
            }
            return log_analysis
        except Exception as e:
            return {"error": str(e), "safety_violation": "Web log analysis failed"}
    
    def _detect_web_attacks(self) -> list[dict]:
        """Detect web-based attack attempts."""
        web_attacks = []
        
        # Common web attack patterns
        attack_patterns = {
            r'\.\.\/|\.\.\\': "Path traversal attempt",
            r'<script[^>]*>.*<\/script>': "XSS attempt",
            r'<.*?on\w+\s*=': "Event handler XSS",
            r'union\s+select': "SQL injection attempt",
            r'or\s+1\s*=\s*1': "SQL injection attempt",
            r'and\s+1\s*=\s*1': "SQL injection attempt",
            r'drop\s+table': "SQL injection attempt",
            r'exec\s*\(': "SQL injection attempt",
            r'\/etc\/passwd': "File inclusion attempt",
            r'\/proc\/': "File inclusion attempt",
            r'cmd\.exe': "Command injection attempt",
            r'powershell': "Command injection attempt",
            r'bash\s+-': "Command injection attempt",
            r'wget\s+': "Command injection attempt",
            r'curl\s+': "Command injection attempt"
        }
        
        access_logs = self._parse_access_logs()
        
        for log_entry in access_logs:
            request = log_entry.get('request', '')
            for pattern, description in attack_patterns.items():
                if re.search(pattern, request, re.IGNORECASE):
                    web_attacks.append({
                        "timestamp": log_entry.get('timestamp'),
                        "ip_address": log_entry.get('ip_address'),
                        "request": request,
                        "user_agent": log_entry.get('user_agent'),
                        "attack_type": description,
                        "pattern": pattern,
                        "severity": self._assess_web_attack_severity(pattern),
                        "mitre_technique": self._map_web_attack_to_mitre(pattern),
                        "log_entry": log_entry
                    })
        
        return web_attacks
    
    def _detect_sql_injection(self) -> list[dict]:
        """Detect SQL injection attempts."""
        sql_injection_attempts = []
        
        sql_injection_patterns = [
            r'union\s+select',
            r'or\s+1\s*=\s*1',
            r'and\s+1\s*=\s*1',
            r'drop\s+table',
            r'exec\s*\(',
            r'waitfor\s+delay',
            r'sleep\s*\(',
            r'benchmark\s*\(',
            r'pg_sleep\s*\(',
            r'dbms_pipe',
            r'xp_cmdshell'
        ]
        
        access_logs = self._parse_access_logs()
        
        for log_entry in access_logs:
            request = log_entry.get('request', '')
            for pattern in sql_injection_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    sql_injection_attempts.append({
                        "timestamp": log_entry.get('timestamp'),
                        "ip_address": log_entry.get('ip_address'),
                        "request": request,
                        "user_agent": log_entry.get('user_agent'),
                        "pattern": pattern,
                        "severity": "high",
                        "mitre_technique": "T1190 - Exploit Public-Facing Application",
                        "log_entry": log_entry
                    })
        
        return sql_injection_attempts
    
    def _detect_xss_attempts(self) -> list[dict]:
        """Detect XSS attempts."""
        xss_attempts = []
        
        xss_patterns = [
            r'<script[^>]*>.*<\/script>',
            r'<.*?on\w+\s*=',
            r'javascript:',
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'eval\s*\(',
            r'fromCharCode',
            r'document\.cookie',
            r'alert\s*\('
        ]
        
        access_logs = self._parse_access_logs()
        
        for log_entry in access_logs:
            request = log_entry.get('request', '')
            for pattern in xss_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    xss_attempts.append({
                        "timestamp": log_entry.get('timestamp'),
                        "ip_address": log_entry.get('ip_address'),
                        "request": request,
                        "user_agent": log_entry.get('user_agent'),
                        "pattern": pattern,
                        "severity": "medium",
                        "mitre_technique": "T1190 - Exploit Public-Facing Application",
                        "log_entry": log_entry
                    })
        
        return xss_attempts
    
    def _detect_path_traversal(self) -> list[dict]:
        """Detect path traversal attempts."""
        path_traversal_attempts = []
        
        traversal_patterns = [
            r'\.\.\/',
            r'\.\.\\',
            r'\.\.%2f',
            r'\.\.%5c',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'\/etc\/passwd',
            r'\/proc\/',
            r'windows\/system32',
            r'c:\\windows\\system32'
        ]
        
        access_logs = self._parse_access_logs()
        
        for log_entry in access_logs:
            request = log_entry.get('request', '')
            for pattern in traversal_patterns:
                if re.search(pattern, request, re.IGNORECASE):
                    path_traversal_attempts.append({
                        "timestamp": log_entry.get('timestamp'),
                        "ip_address": log_entry.get('ip_address'),
                        "request": request,
                        "user_agent": log_entry.get('user_agent'),
                        "pattern": pattern,
                        "severity": "high",
                        "mitre_technique": "T1005 - Data from Local System",
                        "log_entry": log_entry
                    })
        
        return path_traversal_attempts
    
    def _detect_brute_force(self) -> list[dict]:
        """Detect brute force attack attempts."""
        brute_force_attempts = []
        
        # Analyze for repeated failed authentication attempts
        access_logs = self._parse_access_logs()
        
        # Group by IP address
        ip_attempts = {}
        for log_entry in access_logs:
            ip = log_entry.get('ip_address')
            status = log_entry.get('status')
            
            if status in [401, 403, 404]:  # Authentication failures
                if ip not in ip_attempts:
                    ip_attempts[ip] = []
                ip_attempts[ip].append(log_entry)
        
        # Identify potential brute force
        for ip, attempts in ip_attempts.items():
            if len(attempts) > 10:  # Threshold for brute force
                brute_force_attempts.append({
                    "ip_address": ip,
                    "attempt_count": len(attempts),
                    "time_range": self._calculate_time_range(attempts),
                    "severity": "high",
                    "mitre_technique": "T1110 - Brute Force",
                    "description": f"Potential brute force from {ip}"
                })
        
        return brute_force_attempts
```

## MITRE ATT&CK Framework Mapping

### Threat Hunting with MITRE ATT&CK
```python
class MITREAttackMapper:
    """Map log events to MITRE ATT&CK techniques."""
    
    def __init__(self):
        self.mitre_database = self._load_mitre_database()
    
    def map_to_mitre_attack(self, log_events: list[dict]) -> dict:
        """Map log events to MITRE ATT&CK techniques."""
        mitre_mapping = {
            "total_events": len(log_events),
            "mapped_techniques": {},
            "tactics": {},
            "high_priority_techniques": []
        }
        
        for event in log_events:
            technique = self._identify_technique(event)
            if technique:
                technique_id = technique.get('id')
                technique_name = technique.get('name')
                tactic = technique.get('tactic')
                
                # Count technique occurrences
                if technique_id not in mitre_mapping["mapped_techniques"]:
                    mitre_mapping["mapped_techniques"][technique_id] = {
                        "name": technique_name,
                        "tactic": tactic,
                        "count": 0,
                        "events": []
                    }
                
                mitre_mapping["mapped_techniques"][technique_id]["count"] += 1
                mitre_mapping["mapped_techniques"][technique_id]["events"].append(event)
                
                # Count tactics
                if tactic not in mitre_mapping["tactics"]:
                    mitre_mapping["tactics"][tactic] = 0
                mitre_mapping["tactics"][tactic] += 1
        
        # Identify high-priority techniques
        high_priority_techniques = [
            "T1068",  # Privilege Escalation
            "T1003",  # OS Credential Dumping
            "T1021",  # Remote Services
            "T1059",  # Command and Scripting Interpreter
            "T1547",  # Boot or Logon Autostart Execution
        ]
        
        for technique_id in high_priority_techniques:
            if technique_id in mitre_mapping["mapped_techniques"]:
                mitre_mapping["high_priority_techniques"].append({
                    "technique_id": technique_id,
                    "name": mitre_mapping["mapped_techniques"][technique_id]["name"],
                    "count": mitre_mapping["mapped_techniques"][technique_id]["count"]
                })
        
        return mitre_mapping
    
    def _identify_technique(self, event: dict) -> dict | None:
        """Identify MITRE ATT&CK technique from event."""
        event_id = event.get('event_id')
        event_description = event.get('description', '').lower()
        
        # Map events to MITRE techniques
        technique_mapping = {
            # Privilege Escalation
            4672: {"id": "T1068", "name": "Privilege Escalation", "tactic": "Privilege Escalation"},
            4673: {"id": "T1068", "name": "Privilege Escalation", "tactic": "Privilege Escalation"},
            4674: {"id": "T1068", "name": "Privilege Escalation", "tactic": "Privilege Escalation"},
            
            # Credential Access
            4624: {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            4625: {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            4648: {"id": "T1003", "name": "OS Credential Dumping", "tactic": "Credential Access"},
            
            # Lateral Movement
            4624: {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            5140: {"id": "T1021", "name": "Remote Services", "tactic": "Lateral Movement"},
            
            # Persistence
            4688: {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            4697: {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"},
            4720: {"id": "T1547", "name": "Boot or Logon Autostart Execution", "tactic": "Persistence"}
        }
        
        return technique_mapping.get(event_id)
    
    def generate_threat_hunting_report(self, mitre_mapping: dict) -> dict:
        """Generate threat hunting report based on MITRE mapping."""
        report = {
            "executive_summary": self._generate_executive_summary(mitre_mapping),
            "tactic_breakdown": mitre_mapping["tactics"],
            "technique_details": mitre_mapping["mapped_techniques"],
            "high_priority_alerts": mitre_mapping["high_priority_techniques"],
            "investigation_priorities": self._prioritize_investigations(mitre_mapping),
            "remediation_recommendations": self._generate_remediation_recommendations(mitre_mapping)
        }
        return report
```

## Analysis Methodology

### Phase 1: Log Collection and Parsing
1. **Log Identification**: Identify relevant log sources and types
2. **Log Collection**: Collect logs from target systems
3. **Log Parsing**: Parse logs into structured format
4. **Log Normalization**: Normalize log formats for analysis
5. **Log Validation**: Validate log integrity and completeness

### Phase 2: Security Event Analysis
1. **Event Detection**: Detect security events in logs
2. **Pattern Recognition**: Identify attack patterns and sequences
3. **Anomaly Detection**: Detect anomalous behavior
4. **Correlation Analysis**: Correlate events across log sources
5. **Timeline Construction**: Construct attack timeline

### Phase 3: Threat Hunting
1. **Hypothesis Generation**: Generate threat hunting hypotheses
2. **Data Analysis**: Analyze log data for evidence
3. **Pattern Matching**: Match patterns to attack techniques
4. **MITRE Mapping**: Map events to MITRE ATT&CK techniques
5. **Investigation Prioritization**: Prioritize investigations based on risk

## Remediation Guidance

### Windows Security Events
- **Monitor Critical Events**: Monitor critical security event IDs
- **Implement Alerting**: Implement alerting for suspicious events
- **Review Permissions**: Review user and group permissions
- **Audit Changes**: Audit security policy changes
- **Implement SIEM**: Implement SIEM for centralized monitoring

### Linux Security Events
- **Monitor Authentication**: Monitor authentication logs
- **Review Sudo Usage**: Review sudo command usage
- **Monitor SSH**: Monitor SSH access and failures
- **Audit Changes**: Audit system configuration changes
- **Implement Logging**: Implement comprehensive logging

### Web Security Events
- **Monitor Access Logs**: Monitor web server access logs
- **Implement WAF**: Implement web application firewall
- **Rate Limiting**: Implement rate limiting for authentication
- **Input Validation**: Implement proper input validation
- **Security Headers**: Implement security headers

### Threat Hunting
- **Regular Hunts**: Conduct regular threat hunting exercises
- **Hypothesis-Based**: Use hypothesis-based hunting approach
- **Data-Driven**: Use data-driven analysis techniques
- **MITRE Framework**: Use MITRE ATT&CK framework for hunting
- **Continuous Improvement**: Continuously improve hunting techniques

## Safety Compliance

### Operational Boundaries
- **Read-Only Analysis**: All operations are read-only analysis
- **No System Modification**: No modification of target systems
- **Audit Trail**: All operations logged for compliance
- **Data Protection**: Protect sensitive log data
- **Local Lab Only**: Strictly limited to authorized local lab environments

### Ethical Guidelines
- **Authorized Systems**: Only analyze authorized systems
- **Privacy Protection**: Protect user privacy during analysis
- **Data Protection**: Securely handle sensitive log data
- **Responsible Disclosure**: Follow responsible disclosure for critical findings
- **Compliance**: Ensure compliance with relevant regulations

## Pro Tips

1. **Start with Critical Events**: Begin with critical security event IDs
2. **Establish Baselines**: Establish normal activity baselines
3. **Focus on High-Value**: Prioritize high-value assets and users
4. **Correlate Events**: Correlate events across multiple log sources
5. **Use MITRE Framework**: Use MITRE ATT&CK for structured analysis
6. **Automate Detection**: Automate detection of common patterns
7. **Regular Hunts**: Conduct regular threat hunting exercises
8. **Document Findings**: Maintain detailed documentation of findings
9. **Update Regularly**: Keep threat intelligence and patterns updated
10. **Context Matters**: Always consider context when analyzing events

## Summary

DFIR and threat hunting log analysis provides comprehensive security assessment through Windows Event Log analysis, Linux authentication log analysis, web server log analysis, and MITRE ATT&CK framework mapping. The combination of automated detection and manual analysis enables identification of security incidents while maintaining strict safety boundaries for authorized local lab testing. All operations are read-only analysis focused on threat detection and incident response guidance.