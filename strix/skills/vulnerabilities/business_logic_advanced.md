---
name: business-logic-advanced
description: Advanced business logic & state-machine analysis with TOCTOU race conditions, HTTP/2 multiplexing, and parameter tampering
---

# Advanced Business Logic & State-Machine Analysis

This skill extends basic business logic testing with advanced techniques for workflow bypasses, time-of-check-to-time-of-use (TOCTOU) race conditions using HTTP/2 multiplexing, and sophisticated parameter tampering attacks.

## Core Concepts

### State-Machine Abuse
- **State Transition Skipping**: Direct API calls that bypass intermediate states
- **State Reordering**: Executing steps out of the intended sequence
- **State Reversion**: Returning to previous states to exploit temporary privileges
- **State Forking**: Creating parallel state flows to bypass checks

### TOCTOU Race Conditions
- **HTTP/2 Multiplexing**: Concurrent requests that exploit timing windows
- **Check-Then-Act Gaps**: Race conditions between validation and execution
- **Concurrent State Mutation**: Multiple simultaneous state changes
- **Cache Invalidation Races**: Exploiting cache coherence issues

### Parameter Tampering
- **Hidden Field Manipulation**: Modifying client-side computed values
- **Type Confusion**: Submitting unexpected data types
- **Boundary Testing**: Testing numeric limits and edge cases
- **Encoding Attacks**: Alternative encodings to bypass validation

## Advanced Attack Patterns

### 1. Workflow Bypass via State Machine Abuse

#### Pattern: Step Skipping
```python
# Normal flow: browse → cart → checkout → pay → confirm
# Attack: Direct call to confirm with manipulated payment state

# Bypass payment validation
POST /api/checkout/confirm
{
  "order_id": "12345",
  "payment_status": "completed",  // Client-controlled
  "amount": 0.00,                 // Tampered
  "skip_payment": true            // Hidden parameter
}
```

#### Pattern: State Reordering
```python
# Normal: authorize → capture → refund
# Attack: refund before capture or multiple refunds

# Double refund via reordering
POST /api/payments/refund
{ "transaction_id": "tx_123" }  // First refund

POST /api/payments/refund  
{ "transaction_id": "tx_123" }  // Second refund before first completes
```

### 2. TOCTOU Race Conditions with HTTP/2 Multiplexing

#### Pattern: Concurrent Validation Bypass
```python
# Race condition: check quantity availability, then reserve
# HTTP/2 allows simultaneous requests to hit the check before reservation

async def race_quantity_bypass():
    # Send 10 concurrent requests simultaneously
    requests = [
        http2_post("/api/products/123/buy", {"quantity": 1})
        for _ in range(10)
    ]
    responses = await asyncio.gather(*requests)
    # All may succeed if check-then-act isn't atomic
```

#### Pattern: Balance Depletion Race
```python
# Race: check balance → deduct → update
# Multiple concurrent deductions can exceed balance

async def race_balance_debit():
    # Start with $100 balance
    # Send 3 concurrent $50 deduction requests
    tasks = [
        http2_post("/api/account/debit", {"amount": 50})
        for _ in range(3)
    ]
    results = await asyncio.gather(*tasks)
    # May result in -$50 balance if checks aren't atomic
```

### 3. Advanced Parameter Tampering

#### Pattern: Numeric Boundary Exploitation
```python
# Test integer overflow, floating point precision, negative values

test_cases = [
    {"price": -100.00},           // Negative pricing
    {"quantity": 999999999},      // Integer overflow
    {"discount": 101},            // > 100% discount
    {"amount": 1.7976931348623157e+308},  // Max float
    {"amount": 0.0000000001},      // Precision edge case
]
```

#### Pattern: Type Confusion Attacks
```python
# Submit unexpected types to bypass validation

type_confusion_tests = [
    {"price": "free"},            // String instead of number
    {"quantity": [1, 2, 3]},      // Array instead of scalar
    {"enabled": {"admin": true}}, // Object instead of boolean
    {"limit": null},               // Null to bypass checks
    {"count": "0x10"},            // Hexadecimal encoding
]
```

#### Pattern: Hidden Field Manipulation
```python
# Modify fields computed client-side or hidden in forms

hidden_field_attacks = [
    {"total": 0.00},              // Override server-calculated total
    {"tax": 0.00},                // Remove tax calculation
    {"shipping": "free"},         // Force free shipping
    {"premium": true},            // Enable premium features
    {"role": "admin"},            // Privilege escalation
    {"validated": true},           // Skip validation
]
```

## HTTP/2 Multiplexing Techniques

### Concurrent Request Attack
```python
import asyncio
import httpx

async def http2_race_attack(target_url, payload):
    async with httpx.AsyncClient(http2=True) as client:
        # Send multiple requests simultaneously
        tasks = [
            client.post(target_url, json=payload)
            for _ in range(10)  # 10 concurrent requests
        ]
        responses = await asyncio.gather(*tasks)
        return responses
```

### Stream Prioritization Abuse
```python
# Use HTTP/2 stream priorities to exploit timing

async def priority_race_attack(target_url):
    async with httpx.AsyncClient(http2=True) as client:
        # High priority request to create timing window
        high_priority = client.post(
            target_url + "/create",
            json={"data": "setup"},
            headers={"priority": "u=1"}
        )
        
        # Low priority requests to exploit the window
        low_priority = [
            client.post(
                target_url + "/exploit",
                json={"attack": "race"},
                headers={"priority": "u=5"}
            )
            for _ in range(5)
        ]
        
        await asyncio.gather(high_priority, *low_priority)
```

## State-Machine Mapping and Analysis

### 1. Identify State Transitions
```python
# Map out all possible state transitions for critical workflows

state_machine = {
    "order": {
        "states": ["created", "confirmed", "paid", "shipped", "delivered", "cancelled"],
        "transitions": {
            "created": ["confirmed", "cancelled"],
            "confirmed": ["paid", "cancelled"],
            "paid": ["shipped", "refunded"],
            "shipped": ["delivered", "returned"],
            "delivered": ["returned"],
            "cancelled": []  # Terminal state
        }
    }
}
```

### 2. Test Invalid Transitions
```python
# Test transitions that shouldn't be allowed

invalid_transitions = [
    ("created", "shipped"),      # Skip payment
    ("paid", "created"),        # Revert to initial
    ("delivered", "paid"),      # Revert after completion
    ("cancelled", "paid"),      # Reactivate cancelled order
]
```

### 3. Concurrent State Changes
```python
# Test simultaneous state changes to the same resource

async def concurrent_state_updates(order_id):
    tasks = [
        patch_order_state(order_id, "paid"),
        patch_order_state(order_id, "cancelled"),
        patch_order_state(order_id, "shipped")
    ]
    await asyncio.gather(*tasks)
    # Check final state - may be inconsistent
```

## Testing Methodology

### Phase 1: Reconnaissance
1. **Map Workflows**: Identify all critical business workflows
2. **Document States**: List all possible states and transitions
3. **Find Endpoints**: Discover API endpoints for each state transition
4. **Identify Tokens**: Look for session tokens, state IDs, transaction IDs

### Phase 2: State Machine Analysis
1. **Build State Diagram**: Create visual representation of state machine
2. **Identify Invariants**: Determine what should never change (e.g., balance conservation)
3. **Find Guard Conditions**: Locate validation checks for each transition
4. **Test Invalid Transitions**: Attempt disallowed state changes

### Phase 3: Race Condition Testing
1. **Identify Check-Then-Act Patterns**: Look for non-atomic operations
2. **Set Up HTTP/2 Client**: Configure client for multiplexing
3. **Design Race Scenarios**: Create concurrent request patterns
4. **Execute Race Tests**: Run concurrent requests and analyze results

### Phase 4: Parameter Tampering
1. **Enumerate Input Fields**: List all input parameters
2. **Test Type Confusion**: Submit unexpected data types
3. **Test Boundary Cases**: Try extreme values and negative numbers
4. **Test Hidden Fields**: Modify client-side computed values

### Phase 5: Validation
1. **Demonstrate Impact**: Show concrete security impact
2. **Provide Evidence**: Include request/response pairs
3. **Suggest Fixes**: Recommend proper atomic operations and validation
4. **Test Remediation**: Verify fixes prevent exploitation

## Detection Patterns

### Indicators of State Machine Vulnerabilities
- Missing server-side state validation
- Client-side computed totals accepted without verification
- Lack of transactional integrity
- Missing idempotency protections
- No concurrent request handling

### Indicators of Race Condition Vulnerabilities
- Non-atomic check-then-act patterns
- Missing database locks
- Lack of optimistic concurrency control
- No rate limiting on state-changing operations
- Absence of request deduplication

### Indicators of Parameter Tampering Vulnerabilities
- Trust in client-side calculations
- Missing server-side validation
- Weak type checking
- No input sanitization
- Acceptance of unexpected data structures

## Advanced Techniques

### 1. Transaction Rollback Attacks
```python
# Exploit partial failure scenarios to leave system in inconsistent state

async def transaction_rollback_attack():
    # Start transaction that will partially fail
    response1 = await post("/api/orders/create", {"items": [...]})
    order_id = response1.json()["id"]
    
    # Second request that will fail but may not rollback first
    try:
        await post(f"/api/orders/{order_id}/pay", {"invalid": "data"})
    except:
        pass  # Expected to fail
    
    # Check if order exists in inconsistent state
    order = await get(f"/api/orders/{order_id}")
    return order
```

### 2. Cache Coherence Exploitation
```python
# Exploit cache inconsistencies between services

async def cache_coherence_attack():
    # Request from service A (cached)
    response_a = await get("/api/service-a/data")
    
    # Mutate data via service B
    await post("/api/service-b/update", {"data": "new_value"})
    
    # Request from service A again (may return stale cached data)
    response_a_stale = await get("/api/service-a/data")
    
    # Compare with service B (should have new data)
    response_b = await get("/api/service-b/data")
    
    return response_a_stale != response_b
```

### 3. Distributed Transaction Gaps
```python
# Exploit gaps in distributed transaction coordination

async def distributed_transaction_attack():
    # Initiate transaction across multiple services
    tx_id = await post("/api/transactions/start", {
        "operations": [
            {"service": "inventory", "action": "reserve"},
            {"service": "payment", "action": "charge"},
            {"service": "shipping", "action": "schedule"}
        ]
    })
    
    # Exploit timing window between service operations
    await asyncio.sleep(0.1)  # Small delay
    
    # Try to exploit intermediate state
    attack_response = await post("/api/exploit/intermediate", {"tx_id": tx_id})
    
    return attack_response
```

## Remediation Guidance

### For State Machine Vulnerabilities
1. **Server-Side State Validation**: Always validate state transitions server-side
2. **State Invariants**: Enforce business invariants at the database level
3. **Transaction Integrity**: Use database transactions for multi-step operations
4. **Idempotency**: Make state-changing operations idempotent
5. **Audit Logging**: Log all state transitions for analysis

### For Race Condition Vulnerabilities
1. **Atomic Operations**: Use atomic database operations
2. **Optimistic Concurrency**: Implement version checks or timestamps
3. **Pessimistic Locking**: Use database locks for critical sections
4. **Request Deduplication**: Deduplicate concurrent identical requests
5. **Rate Limiting**: Implement rate limiting on state-changing operations

### For Parameter Tampering Vulnerabilities
1. **Server-Side Validation**: Never trust client-side calculations
2. **Strong Typing**: Enforce strict type checking
3. **Input Sanitization**: Sanitize and validate all inputs
4. **Allowlist Validation**: Use allowlists rather than blocklists
5. **Schema Validation**: Use strict schema validation (e.g., JSON Schema)

## Testing Tools and Techniques

### HTTP/2 Testing
- **httpx**: Python HTTP client with HTTP/2 support
- **curl**: HTTP/2 enabled curl for manual testing
- **wrk**: HTTP benchmarking tool for concurrent requests

### State Machine Analysis
- **Graph Visualization**: Use graphviz or similar tools
- **Model-Based Testing**: Generate test cases from state models
- **Property-Based Testing**: Use hypothesis or similar tools

### Race Condition Detection
- **Thread Sanitizer**: Detect data races in code
- **Concurrency Testing**: Use Jepsen or similar tools
- **Load Testing**: Simulate high concurrent load

## Impact Assessment

### Business Logic Vulnerabilities
- **Financial Impact**: Direct monetary loss through fraud
- **Regulatory Impact**: Violations of financial regulations
- **Reputation Impact**: Loss of customer trust
- **Operational Impact**: Disruption of business processes

### Race Condition Vulnerabilities
- **Data Integrity**: Corrupted or inconsistent data
- **Resource Exhaustion**: Depletion of limited resources
- **Privilege Escalation**: Unauthorized access to features
- **Denial of Service**: System instability under load

### Parameter Tampering Vulnerabilities
- **Security Bypass**: Circumvention of security controls
- **Privilege Escalation**: Unauthorized access to admin functions
- **Data Manipulation**: Unauthorized modification of data
- **System Compromise**: Complete system takeover

## Pro Tips

1. **Start with State Mapping**: Understand the business logic before testing
2. **Use HTTP/2 for Race Testing**: Leverage multiplexing for effective race conditions
3. **Test Concurrent Operations**: Many vulnerabilities only appear under concurrent load
4. **Automate State Machine Testing**: Use model-based testing for comprehensive coverage
5. **Monitor for Inconsistencies**: Look for data inconsistencies that indicate race conditions
6. **Test Transaction Boundaries**: Pay special attention to distributed transaction boundaries
7. **Verify Idempotency**: Ensure all state-changing operations are idempotent
8. **Check Cache Coherence**: Verify cache invalidation across services
9. **Test Error Handling**: Exploit error handling paths for state manipulation
10. **Document Invariants**: Clearly document business invariants for reference

## Summary

Advanced business logic and state-machine analysis requires deep understanding of the application's business rules and careful design of test cases that exploit timing windows, concurrent operations, and trust relationships. The combination of state machine abuse, TOCTOU race conditions, and parameter tampering provides a powerful toolkit for finding critical business logic vulnerabilities.