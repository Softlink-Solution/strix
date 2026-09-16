---
name: agentic-self-correction
description: Agentic self-correction loop for parsing syntax errors, WAF blocks, and intelligent payload mutation with iterative refinement
---

# Agentic Self-Correction Loop

This skill implements an intelligent self-correction mechanism that parses errors, adapts to WAF blocks, and mutates payloads through iterative refinement (up to 3 iterations) before falling back to alternative strategies.

## Core Concept

The agentic self-correction loop enables security testing agents to:
1. **Parse and classify errors** (syntax errors, WAF blocks, validation failures)
2. **Intelligently mutate payloads** based on error feedback
3. **Iteratively refine attacks** with bounded exploration (max 3 iterations)
4. **Fall back gracefully** when initial approaches fail
5. **Learn from patterns** to improve future attempts

## Error Classification and Parsing

### Error Types

#### 1. Syntax Errors
```python
# HTTP response codes and patterns indicating syntax issues
syntax_error_patterns = {
    "json_syntax": [400, "JSON parse error", "Invalid JSON", "Malformed JSON"],
    "xml_syntax": [400, "XML parse error", "Invalid XML", "Malformed XML"],
    "sql_syntax": [500, "SQL syntax error", "Query syntax", "Invalid SQL"],
    "command_syntax": [500, "Command syntax", "Invalid command", "Parse error"],
}
```

#### 2. WAF Blocks
```python
# WAF-specific response patterns
waf_block_patterns = {
    "generic_waf": [403, "Forbidden", "WAF", "Firewall", "Blocked"],
    "mod_security": [403, "ModSecurity", "ModSecurity Rule"],
    "cloudflare": [403, "Cloudflare", "Attention Required", "Error 1020"],
    "aws_waf": [403, "AWS WAF", "Request blocked"],
    "akamai": [403, "Akamai", "Access Denied"],
}
```

#### 3. Validation Errors
```python
# Input validation failure patterns
validation_error_patterns = {
    "type_validation": [400, "Invalid type", "Type mismatch", "Expected"],
    "length_validation": [400, "Too long", "Too short", "Length"],
    "format_validation": [400, "Invalid format", "Format", "Pattern"],
    "range_validation": [400, "Out of range", "Range", "Must be between"],
}
```

### Error Parser Implementation
```python
import re
from typing import Dict, Any

class ErrorParser:
    """Parse and classify HTTP errors for intelligent response."""
    
    def __init__(self):
        self.patterns = {
            **syntax_error_patterns,
            **waf_block_patterns,
            **validation_error_patterns
        }
    
    def parse_error(self, status_code: int, response_text: str) -> Dict[str, Any]:
        """Parse error response and classify error type."""
        error_info = {
            "status_code": status_code,
            "error_type": "unknown",
            "confidence": 0.0,
            "details": {},
            "suggested_actions": []
        }
        
        # Check against known patterns
        for error_type, patterns in self.patterns.items():
            for pattern in patterns:
                if isinstance(pattern, int) and pattern == status_code:
                    error_info["error_type"] = error_type
                    error_info["confidence"] = 0.8
                    error_info["suggested_actions"] = self._get_actions(error_type)
                    break
                elif isinstance(pattern, str) and pattern.lower() in response_text.lower():
                    error_info["error_type"] = error_type
                    error_info["confidence"] = 0.7
                    error_info["suggested_actions"] = self._get_actions(error_type)
                    break
        
        # Extract additional details from response
        error_info["details"] = self._extract_details(response_text)
        
        return error_info
    
    def _get_actions(self, error_type: str) -> list[str]:
        """Get suggested actions based on error type."""
        actions = {
            "json_syntax": ["Validate JSON structure", "Escape special characters", "Check quotation marks"],
            "xml_syntax": ["Validate XML structure", "Check tag nesting", "Verify encoding"],
            "sql_syntax": ["Escape SQL characters", "Check quote usage", "Simplify query structure"],
            "generic_waf": ["Obfuscate payload", "Change encoding", "Reduce payload size"],
            "mod_security": ["Evade specific rules", "Alternate payload structure", "Use different injection point"],
            "cloudflare": ["Reduce request rate", "Change User-Agent", "Use different origin"],
            "type_validation": ["Check data types", "Convert to expected format", "Use schema-compliant values"],
            "length_validation": ["Truncate values", "Use shorter alternatives", "Split into multiple requests"],
        }
        return actions.get(error_type, ["Analyze error details", "Try alternative approach"])
    
    def _extract_details(self, response_text: str) -> Dict[str, Any]:
        """Extract structured details from error response."""
        details = {
            "error_message": "",
            "error_code": "",
            "request_id": "",
            "stack_trace": ""
        }
        
        # Extract common error message patterns
        message_match = re.search(r'error["\s:]+([^"\n]+)', response_text, re.IGNORECASE)
        if message_match:
            details["error_message"] = message_match.group(1)
        
        # Extract error codes
        code_match = re.search(r'code["\s:]+(\d+|[A-Z0-9_-]+)', response_text, re.IGNORECASE)
        if code_match:
            details["error_code"] = code_match.group(1)
        
        # Extract request IDs
        request_id_match = re.search(r'request[_\s]?id["\s:]+([A-Za-z0-9-]+)', response_text, re.IGNORECASE)
        if request_id_match:
            details["request_id"] = request_id_match.group(1)
        
        return details
```

## Payload Mutation Strategies

### Mutation Engine
```python
from typing import Any, List
import random
import string

class PayloadMutator:
    """Intelligent payload mutation based on error feedback."""
    
    def __init__(self, max_iterations: int = 3):
        self.max_iterations = max_iterations
        self.iteration_count = 0
        self.mutation_history = []
    
    def mutate_payload(self, original_payload: Any, error_info: Dict[str, Any]) -> Any:
        """Mutate payload based on error type and iteration count."""
        if self.iteration_count >= self.max_iterations:
            return None  # Exhausted iterations
        
        self.iteration_count += 1
        error_type = error_info.get("error_type", "unknown")
        
        mutation_strategies = {
            "json_syntax": self._mutate_json_syntax,
            "xml_syntax": self._mutate_xml_syntax,
            "sql_syntax": self._mutate_sql_syntax,
            "generic_waf": self._mutate_waf_evasion,
            "mod_security": self._mutate_mod_security_evasion,
            "cloudflare": self._mutate_cloudflare_evasion,
            "type_validation": self._mutate_type_validation,
            "length_validation": self._mutate_length_validation,
        }
        
        strategy = mutation_strategies.get(error_type, self._mutate_generic)
        mutated_payload = strategy(original_payload, error_info)
        
        self.mutation_history.append({
            "iteration": self.iteration_count,
            "error_type": error_type,
            "original": original_payload,
            "mutated": mutated_payload
        })
        
        return mutated_payload
    
    def _mutate_json_syntax(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Fix JSON syntax errors."""
        if isinstance(payload, str):
            try:
                # Try to parse and re-serialize to fix syntax
                import json
                parsed = json.loads(payload)
                return json.dumps(parsed)
            except json.JSONDecodeError:
                # Apply common JSON fixes
                payload = payload.replace("'", '"')  # Single to double quotes
                payload = re.sub(r',\s*([}\]])', r'\1', payload)  # Trailing commas
                return payload
        return payload
    
    def _mutate_sql_syntax(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Fix SQL syntax errors and attempt evasion."""
        if isinstance(payload, str):
            # Common SQL evasion techniques
            mutations = [
                lambda x: x.replace("'", "''"),  # Quote escaping
                lambda x: x.replace(" ", "/**/"),  # Comment obfuscation
                lambda x: x.replace("OR", "||"),  # Operator substitution
                lambda x: x.upper(),  # Case variation
                lambda x: x.lower(),  # Case variation
            ]
            # Apply random mutation
            mutation = random.choice(mutations)
            return mutation(payload)
        return payload
    
    def _mutate_waf_evasion(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Apply WAF evasion techniques."""
        if isinstance(payload, str):
            mutations = [
                lambda x: self._encode_url(x),
                lambda x: self._encode_hex(x),
                lambda x: self._add_unicode_evasion(x),
                lambda x: self._fragment_payload(x),
            ]
            mutation = random.choice(mutations)
            return mutation(payload)
        return payload
    
    def _mutate_mod_security_evasion(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Specific ModSecurity evasion techniques."""
        if isinstance(payload, str):
            # ModSecurity-specific evasion
            mutations = [
                lambda x: x.replace(" ", "%09"),  # Horizontal tab
                lambda x: x.replace(" ", "%20"),  # Space encoding
                lambda x: self._add_null_bytes(x),
                lambda x: self._alternate_case(x),
            ]
            mutation = random.choice(mutations)
            return mutation(payload)
        return payload
    
    def _mutate_cloudflare_evasion(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Cloudflare-specific evasion techniques."""
        if isinstance(payload, str):
            # Reduce payload size and apply obfuscation
            if len(payload) > 1000:
                payload = payload[:1000]  # Truncate large payloads
            mutations = [
                lambda x: self._compress_payload(x),
                lambda x: self._encode_base64(x),
                lambda x: self._remove_common_patterns(x),
            ]
            mutation = random.choice(mutations)
            return mutation(payload)
        return payload
    
    def _mutate_type_validation(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Fix type validation errors."""
        # Try common type conversions
        if isinstance(payload, str):
            # Try numeric conversion
            try:
                return int(payload)
            except ValueError:
                try:
                    return float(payload)
                except ValueError:
                    pass
            # Try boolean conversion
            if payload.lower() in ("true", "false"):
                return payload.lower() == "true"
        return payload
    
    def _mutate_length_validation(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Fix length validation errors."""
        if isinstance(payload, str):
            # Truncate to reasonable length
            max_length = 255  # Common limit
            if len(payload) > max_length:
                return payload[:max_length]
        return payload
    
    def _mutate_generic(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Generic mutation strategy."""
        if isinstance(payload, str):
            # Apply random character modifications
            if len(payload) > 0:
                mutation_methods = [
                    lambda x: x[:-1],  # Remove last character
                    lambda x: x + random.choice(string.ascii_letters),  # Add random char
                    lambda x: x.swapcase(),  # Swap case
                    lambda x: x.replace(" ", ""),  # Remove spaces
                ]
                mutation = random.choice(mutation_methods)
                return mutation(payload)
        return payload
    
    # Helper methods for evasion techniques
    def _encode_url(self, payload: str) -> str:
        """URL encode the payload."""
        import urllib.parse
        return urllib.parse.quote(payload)
    
    def _encode_hex(self, payload: str) -> str:
        """Hex encode the payload."""
        return payload.encode().hex()
    
    def _encode_base64(self, payload: str) -> str:
        """Base64 encode the payload."""
        import base64
        return base64.b64encode(payload.encode()).decode()
    
    def _add_unicode_evasion(self, payload: str) -> str:
        """Add Unicode evasion characters."""
        unicode_chars = ["\u0000", "\u00a0", "\u200b", "\u200c"]
        return payload + random.choice(unicode_chars)
    
    def _add_null_bytes(self, payload: str) -> str:
        """Add null bytes for evasion."""
        return payload.replace(" ", "\x00")
    
    def _alternate_case(self, payload: str) -> str:
        """Alternate character case for evasion."""
        result = []
        for i, char in enumerate(payload):
            if i % 2 == 0:
                result.append(char.upper())
            else:
                result.append(char.lower())
        return ''.join(result)
    
    def _fragment_payload(self, payload: str) -> str:
        """Fragment payload for evasion."""
        mid = len(payload) // 2
        return payload[:mid] + "%" + payload[mid:]
    
    def _compress_payload(self, payload: str) -> str:
        """Compress payload by removing redundancy."""
        # Remove repeated characters
        compressed = []
        prev_char = None
        for char in payload:
            if char != prev_char:
                compressed.append(char)
                prev_char = char
        return ''.join(compressed)
    
    def _remove_common_patterns(self, payload: str) -> str:
        """Remove common WAF detection patterns."""
        # Remove common malicious patterns
        patterns = ["<script>", "javascript:", "onerror=", "onload=", "eval("]
        result = payload
        for pattern in patterns:
            result = result.replace(pattern, "")
        return result
    
    def reset(self) -> None:
        """Reset iteration counter and history."""
        self.iteration_count = 0
        self.mutation_history = []
```

## Self-Correction Loop Implementation

### Main Loop Controller
```python
from typing import Callable, Any, Optional
import asyncio

class SelfCorrectionLoop:
    """Main self-correction loop controller."""
    
    def __init__(self, max_iterations: int = 3):
        self.error_parser = ErrorParser()
        self.payload_mutator = PayloadMutator(max_iterations)
        self.max_iterations = max_iterations
        self.success_callbacks = []
        self.failure_callbacks = []
    
    async def execute_with_correction(
        self,
        initial_payload: Any,
        execute_function: Callable[[Any], Any],
        context: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Execute payload with self-correction loop."""
        context = context or {}
        current_payload = initial_payload
        attempt_history = []
        
        for attempt in range(self.max_iterations + 1):  # +1 for initial attempt
            try:
                # Execute the payload
                result = await execute_function(current_payload)
                
                # Check if execution was successful
                if self._is_success(result):
                    success_info = {
                        "success": True,
                        "attempt": attempt + 1,
                        "payload": current_payload,
                        "result": result,
                        "history": attempt_history
                    }
                    await self._notify_success(success_info)
                    return success_info
                
                # Parse the error from result
                error_info = self._parse_result_error(result)
                attempt_history.append({
                    "attempt": attempt + 1,
                    "payload": current_payload,
                    "error": error_info
                })
                
                # Mutate payload for next attempt
                mutated_payload = self.payload_mutator.mutate_payload(
                    current_payload, error_info
                )
                
                if mutated_payload is None:
                    # Exhausted iterations
                    break
                
                current_payload = mutated_payload
                
            except Exception as e:
                # Handle execution exceptions
                error_info = {
                    "error_type": "execution_error",
                    "confidence": 1.0,
                    "details": {"exception": str(e)},
                    "suggested_actions": ["Check execution environment", "Verify permissions"]
                }
                attempt_history.append({
                    "attempt": attempt + 1,
                    "payload": current_payload,
                    "error": error_info
                })
                
                # Try mutation on exception
                mutated_payload = self.payload_mutator.mutate_payload(
                    current_payload, error_info
                )
                
                if mutated_payload is None:
                    break
                
                current_payload = mutated_payload
        
        # All attempts failed
        failure_info = {
            "success": False,
            "attempts": attempt + 1,
            "final_payload": current_payload,
            "history": attempt_history
        }
        await self._notify_failure(failure_info)
        return failure_info
    
    def _is_success(self, result: Any) -> bool:
        """Determine if execution was successful."""
        if isinstance(result, dict):
            # Check for success indicators
            status_code = result.get("status_code", 0)
            if 200 <= status_code < 300:
                return True
            # Check for explicit success flag
            if result.get("success", False):
                return True
            # Check for absence of error indicators
            if not result.get("error") and not result.get("exception"):
                return True
        return False
    
    def _parse_result_error(self, result: Any) -> Dict[str, Any]:
        """Parse error information from execution result."""
        if isinstance(result, dict):
            status_code = result.get("status_code", 0)
            response_text = result.get("text", "") or result.get("content", "")
            return self.error_parser.parse_error(status_code, response_text)
        return {
            "error_type": "unknown",
            "confidence": 0.0,
            "details": {},
            "suggested_actions": ["Analyze result structure"]
        }
    
    async def _notify_success(self, success_info: Dict[str, Any]) -> None:
        """Notify success callbacks."""
        for callback in self.success_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(success_info)
                else:
                    callback(success_info)
            except Exception as e:
                print(f"Success callback error: {e}")
    
    async def _notify_failure(self, failure_info: Dict[str, Any]) -> None:
        """Notify failure callbacks."""
        for callback in self.failure_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(failure_info)
                else:
                    callback(failure_info)
            except Exception as e:
                print(f"Failure callback error: {e}")
    
    def on_success(self, callback: Callable) -> None:
        """Register success callback."""
        self.success_callbacks.append(callback)
    
    def on_failure(self, callback: Callable) -> None:
        """Register failure callback."""
        self.failure_callbacks.append(callback)
    
    def reset(self) -> None:
        """Reset the correction loop state."""
        self.payload_mutator.reset()
```

## Integration with Security Testing

### Example: SQL Injection with Self-Correction
```python
async def test_sqli_with_correction(target_url: str, param: str):
    """Test SQL injection with self-correction loop."""
    
    async def execute_sqli(payload: str):
        async with httpx.AsyncClient() as client:
            response = await client.get(
                target_url,
                params={param: payload}
            )
            return {
                "status_code": response.status_code,
                "text": response.text,
                "headers": dict(response.headers)
            }
    
    # Initial SQL injection payload
    initial_payload = "' OR '1'='1"
    
    # Create self-correction loop
    correction_loop = SelfCorrectionLoop(max_iterations=3)
    
    # Set up callbacks
    def on_success(success_info):
        print(f"SQL Injection successful on attempt {success_info['attempt']}")
        print(f"Successful payload: {success_info['payload']}")
    
    def on_failure(failure_info):
        print(f"SQL Injection failed after {failure_info['attempts']} attempts")
        print(f"Final payload: {failure_info['final_payload']}")
        print("Attempt history:")
        for attempt in failure_info['history']:
            print(f"  Attempt {attempt['attempt']}: {attempt['error']['error_type']}")
    
    correction_loop.on_success(on_success)
    correction_loop.on_failure(on_failure)
    
    # Execute with self-correction
    result = await correction_loop.execute_with_correction(
        initial_payload,
        execute_sqli
    )
    
    return result
```

### Example: XSS with WAF Evasion
```python
async def test_xss_with_correction(target_url: str, param: str):
    """Test XSS with WAF evasion self-correction."""
    
    async def execute_xss(payload: str):
        async with httpx.AsyncClient() as client:
            response = await client.post(
                target_url,
                data={param: payload}
            )
            return {
                "status_code": response.status_code,
                "text": response.text,
                "headers": dict(response.headers)
            }
    
    # Initial XSS payload
    initial_payload = "<script>alert('XSS')</script>"
    
    # Create self-correction loop
    correction_loop = SelfCorrectionLoop(max_iterations=3)
    
    # Execute with self-correction
    result = await correction_loop.execute_with_correction(
        initial_payload,
        execute_xss
    )
    
    return result
```

## Advanced Features

### Pattern Learning
```python
class PatternLearner:
    """Learn from successful mutations for future reference."""
    
    def __init__(self):
        self.successful_patterns = {}
        self.failed_patterns = {}
    
    def record_success(self, error_type: str, mutation: str) -> None:
        """Record successful mutation pattern."""
        if error_type not in self.successful_patterns:
            self.successful_patterns[error_type] = []
        self.successful_patterns[error_type].append(mutation)
    
    def record_failure(self, error_type: str, mutation: str) -> None:
        """Record failed mutation pattern."""
        if error_type not in self.failed_patterns:
            self.failed_patterns[error_type] = []
        self.failed_patterns[error_type].append(mutation)
    
    def suggest_mutation(self, error_type: str) -> Optional[str]:
        """Suggest mutation based on past successes."""
        if error_type in self.successful_patterns:
            # Return most recently successful mutation
            return self.successful_patterns[error_type][-1]
        return None
```

### Context-Aware Mutation
```python
class ContextAwareMutator(PayloadMutator):
    """Payload mutator that considers application context."""
    
    def __init__(self, max_iterations: int = 3, context: Optional[Dict[str, Any]] = None):
        super().__init__(max_iterations)
        self.context = context or {}
    
    def mutate_payload(self, original_payload: Any, error_info: Dict[str, Any]) -> Any:
        """Mutate payload considering application context."""
        # Apply context-specific mutations
        if self.context.get("application_type") == "api":
            return self._mutate_for_api(original_payload, error_info)
        elif self.context.get("application_type") == "web":
            return self._mutate_for_web(original_payload, error_info)
        else:
            return super().mutate_payload(original_payload, error_info)
    
    def _mutate_for_api(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """API-specific mutations."""
        if isinstance(payload, dict):
            # API-specific modifications
            if "headers" not in payload:
                payload["headers"] = {}
            payload["headers"]["User-Agent"] = self._get_random_user_agent()
        return payload
    
    def _mutate_for_web(self, payload: Any, error_info: Dict[str, Any]) -> Any:
        """Web application-specific mutations."""
        if isinstance(payload, str):
            # Web-specific obfuscation
            payload = self._html_encode(payload)
        return payload
    
    def _get_random_user_agent(self) -> str:
        """Get random user agent string."""
        user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
            "Mozilla/5.0 (X11; Linux x86_64)"
        ]
        return random.choice(user_agents)
    
    def _html_encode(self, payload: str) -> str:
        """HTML encode payload."""
        html_entities = {
            "<": "&lt;",
            ">": "&gt;",
            "\"": "&quot;",
            "'": "&#x27;",
            "/": "&#x2F;"
        }
        for char, entity in html_entities.items():
            payload = payload.replace(char, entity)
        return payload
```

## Fallback Strategies

### Exhaustion Handler
```python
class ExhaustionHandler:
    """Handle cases where mutation iterations are exhausted."""
    
    def __init__(self):
        self.fallback_strategies = [
            self._fallback_reconnaissance,
            self._fallback_alternative_vector,
            self._fallback_delayed_retry,
            self._fallback_manual_review
        ]
    
    async def handle_exhaustion(
        self,
        original_payload: Any,
        attempt_history: list,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Handle mutation exhaustion with fallback strategies."""
        for strategy in self.fallback_strategies:
            try:
                result = await strategy(original_payload, attempt_history, context)
                if result.get("success"):
                    return result
            except Exception as e:
                print(f"Fallback strategy failed: {e}")
                continue
        
        return {"success": False, "message": "All fallback strategies exhausted"}
    
    async def _fallback_reconnaissance(
        self,
        original_payload: Any,
        attempt_history: list,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback to additional reconnaissance."""
        print("Attempting reconnaissance fallback...")
        # Implement additional reconnaissance logic
        return {"success": False, "message": "Reconnaissance found no new vectors"}
    
    async def _fallback_alternative_vector(
        self,
        original_payload: Any,
        attempt_history: list,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback to alternative attack vectors."""
        print("Attempting alternative vector fallback...")
        # Implement alternative vector logic
        return {"success": False, "message": "Alternative vectors unsuccessful"}
    
    async def _fallback_delayed_retry(
        self,
        original_payload: Any,
        attempt_history: list,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback to delayed retry with timing variation."""
        print("Attempting delayed retry fallback...")
        await asyncio.sleep(random.uniform(1, 5))
        # Implement delayed retry logic
        return {"success": False, "message": "Delayed retry unsuccessful"}
    
    async def _fallback_manual_review(
        self,
        original_payload: Any,
        attempt_history: list,
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback to manual review recommendation."""
        print("Recommending manual review...")
        return {
            "success": False,
            "message": "Manual review required",
            "recommendation": "Review attack logic and target application behavior"
        }
```

## Testing and Validation

### Unit Testing
```python
import pytest

def test_error_parser():
    parser = ErrorParser()
    
    # Test JSON syntax error
    error_info = parser.parse_error(400, "Invalid JSON syntax")
    assert error_info["error_type"] == "json_syntax"
    
    # Test WAF block
    error_info = parser.parse_error(403, "Blocked by WAF")
    assert error_info["error_type"] == "generic_waf"

def test_payload_mutator():
    mutator = PayloadMutator(max_iterations=3)
    
    # Test JSON syntax mutation
    original = "{'key': 'value'}"  # Invalid JSON (single quotes)
    error_info = {"error_type": "json_syntax"}
    mutated = mutator.mutate_payload(original, error_info)
    assert '"' in mutated  # Should have double quotes
    
    # Test iteration limit
    for i in range(5):
        mutator.mutate_payload("test", {"error_type": "unknown"})
    assert mutator.iteration_count == 3  # Should respect max

@pytest.mark.asyncio
async def test_self_correction_loop():
    loop = SelfCorrectionLoop(max_iterations=2)
    
    async def mock_execute(payload):
        if "success" in payload:
            return {"status_code": 200, "text": "Success"}
        return {"status_code": 400, "text": "Invalid JSON"}
    
    result = await loop.execute_with_correction(
        "initial",
        mock_execute
    )
    
    assert "success" in result
    assert "history" in result
```

## Best Practices

### 1. Iteration Boundaries
- **Max 3 iterations**: Prevents infinite loops and resource exhaustion
- **Exponential backoff**: Add delays between iterations to avoid rate limiting
- **Context preservation**: Maintain context across iterations for learning

### 2. Error Handling
- **Graceful degradation**: Always have fallback strategies
- **Detailed logging**: Record all attempts and mutations for analysis
- **Pattern recognition**: Learn from successful mutations

### 3. Performance Considerations
- **Async execution**: Use async/await for concurrent operations
- **Resource limits**: Set timeouts and memory limits
- **Cancellation support**: Allow cancellation of long-running loops

### 4. Security Considerations
- **Payload sanitization**: Avoid introducing new vulnerabilities
- **Rate limiting**: Respect target rate limits
- **Compliance**: Ensure testing activities remain authorized

## Pro Tips

1. **Start Simple**: Begin with basic error classification before complex mutations
2. **Learn from Failures**: Record failed mutations to avoid repeating mistakes
3. **Context Matters**: Consider application type and technology stack
4. **Rate Awareness**: Be mindful of rate limits and WAF thresholds
5. **Monitor Progress**: Track iteration progress and success rates
6. **Fallback Planning**: Always have multiple fallback strategies
7. **Pattern Recognition**: Identify recurring error patterns for optimization
8. **Human-in-the-Loop**: Provide manual review options for complex cases
9. **Resource Management**: Set appropriate timeouts and resource limits
10. **Continuous Learning**: Update mutation strategies based on new attack techniques

## Summary

The agentic self-correction loop provides intelligent, adaptive security testing by parsing errors, mutating payloads iteratively, and falling back gracefully when approaches fail. This system enables more effective testing while respecting operational boundaries and learning from experience.