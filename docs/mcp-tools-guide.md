# MCP Tools Guide - CTF Solver Integration

## Overview

HexStrike AI v6.0 exposes **156 total tools** through the MCP (Model Context Protocol) interface, enabling AI agents like Claude, GPT-4, and GitHub Copilot to automate cybersecurity workflows.

This guide covers the **12 new CTF solver tools** added in v6.0 for challenge automation.

---

## CTF Solver Tools (12 Tools)

### 1. Challenge Classification

#### `ctf_classify_challenge`

Automatically detect and classify CTF challenge type with recommended solving tools.

**Input Parameters:**
```python
description: str          # Challenge description text
files: str               # Comma-separated filenames (optional)
hints: str               # Comma-separated hints (optional)
url: str                 # Challenge URL if web-based (optional)
```

**Returns:**
```python
{
    "success": bool,                 # Classification succeeded
    "category": str,                 # CRYPTO, PWN, WEB, REVERSE, FORENSICS, etc.
    "confidence": float,             # 0.0 to 1.0 confidence score
    "subtype": str,                  # Specific challenge type (RSA, format_string, etc.)
    "recommended_tools": [str],      # Tool names to use
    "keywords_matched": [str],       # Matching keywords from description
    "file_indicators": [str],        # Files that revealed category
    "analysis_notes": [str]          # Additional analysis details
}
```

**Example Usage:**
```python
result = ctf_classify_challenge(
    description="We have an RSA key with very large e and small d. Decrypt the message.",
    files="key.pub,ciphertext.txt",
    hints="Check if e is unusually large"
)
# Returns: category=CRYPTO, subtype=RSA,
#          recommended_tools=[ctf_rsa_auto_attack, ctf_rsa_wiener_attack]
```

---

### 2. RSA Solver Tools (3 Tools)

#### `ctf_rsa_auto_attack`

Automatically select and execute the best RSA attack based on parameters.

**Input Parameters:**
```python
n: str               # RSA modulus (decimal string or hex)
e: str = "65537"     # Public exponent (default: 65537)
c: str = ""          # Ciphertext to decrypt (optional)
timeout: int = 60    # Maximum execution time in seconds
```

**Returns:**
```python
{
    "success": bool,              # Attack succeeded
    "attack_type": str,           # wiener, fermat, factordb, small_e, etc.
    "message": str,               # Status message
    "p": int,                     # First prime factor (if recovered)
    "q": int,                     # Second prime factor (if recovered)
    "d": int,                     # Private exponent (if recovered)
    "plaintext": int,             # Decrypted message (if recovered)
    "plaintext_hex": str,         # Plaintext as hex
    "flag": str,                  # Extracted flag/message
    "execution_time": float,      # Time taken in seconds
    "details": dict               # Additional attack details
}
```

**Example Usage:**
```python
result = ctf_rsa_auto_attack(
    n="123456789012345678901234567890",
    e="65537",
    c="987654321098765432109876543210"
)
# If successful: {"success": true, "attack_type": "fermat", "plaintext": ...}
```

#### `ctf_rsa_wiener_attack`

Execute Wiener's attack for RSA with large public exponent and small private exponent.

**Input Parameters:**
```python
n: str               # RSA modulus
e: str               # Public exponent (should be large, like > 2^30)
c: str = ""          # Ciphertext (optional)
```

**Returns:** Same format as `ctf_rsa_auto_attack`

**When to Use:**
- e is unusually large (> 2^30)
- d is suspected to be small (d < N^0.25)
- Other attacks have failed

**Example:**
```python
result = ctf_rsa_wiener_attack(
    n="987654321098765432109876543210",
    e="123456789012345678901234567890"
)
```

#### `ctf_rsa_fermat_attack`

Execute Fermat factorization for RSA with close prime factors.

**Input Parameters:**
```python
n: str                        # RSA modulus
e: str = "65537"              # Public exponent
c: str = ""                   # Ciphertext (optional)
max_iterations: int = 10000   # Maximum factorization attempts
```

**Returns:** Same format as `ctf_rsa_auto_attack`

**When to Use:**
- p and q are very close to each other
- p and q differ by small amount (|p-q| < 2^(n_bits/2 - 10))
- Standard factorization is slow

**Example:**
```python
result = ctf_rsa_fermat_attack(
    n="949406050000103423",  # Product of close primes
    e="65537"
)
```

---

### 3. Format String Solver Tools (2 Tools)

#### `ctf_format_string_arbitrary_write`

Generate format string payload for arbitrary memory write.

**Input Parameters:**
```python
address: str         # Target memory address (hex, e.g., "0x601020")
value: str           # Value to write (hex, e.g., "0xdeadbeef")
offset: int          # Format string offset (where input appears on stack)
arch: str = "x64"    # Target architecture: x64, x86, arm, arm64
```

**Returns:**
```python
{
    "success": bool,           # Payload generation succeeded
    "payload_hex": str,        # Payload as hex string
    "payload_ascii": str,      # Payload as ASCII (if printable)
    "description": str,        # How the payload works
    "writes": [
        {
            "address": str,    # Target address (hex)
            "value": str       # Value written (hex)
        }
    ]
}
```

**Example Usage:**
```python
result = ctf_format_string_arbitrary_write(
    address="0x601020",        # Address to write to
    value="0xdeadbeef",        # Value to write
    offset=6,                  # Found at position 6 on stack
    arch="x64"
)
# Returns payload to inject into format string vulnerability
```

#### `ctf_format_string_got_overwrite`

Generate GOT (Global Offset Table) overwrite payload.

**Input Parameters:**
```python
got_entry: str         # GOT entry address to overwrite (hex)
target_addr: str       # Address to redirect to (hex)
offset: int            # Format string offset
arch: str = "x64"      # Target architecture
```

**Returns:** Same format as `ctf_format_string_arbitrary_write`

**Example Usage:**
```python
result = ctf_format_string_got_overwrite(
    got_entry="0x601018",      # malloc GOT entry
    target_addr="0x400686",    # Address of system()
    offset=6
)
# Redirects malloc to system() for code execution
```

---

### 4. ROP Builder Tools (2 Tools)

#### `ctf_rop_build_execve_chain`

Build ROP chain to execute `/bin/sh` system call.

**Input Parameters:**
```python
gadgets_json: str      # JSON string with gadgets: {"POP_RDI": {"address": "0x400686", "instructions": "pop rdi; ret"}, ...}
binsh_addr: str        # Address of "/bin/sh" string in memory (hex)
arch: str = "x64"      # Target architecture: x64 or x86
```

**Returns:**
```python
{
    "success": bool,
    "chain_hex": str,                 # Complete ROP chain as hex
    "chain_length": int,              # Length of chain in bytes
    "description": str,               # How the chain works
    "gadgets_used": [
        {
            "address": str,           # Gadget address
            "instructions": str       # Gadget instructions
        }
    ],
    "chain_dump": str                 # Disassembly of chain
}
```

**Example Usage:**
```python
gadgets_json = '''{
    "POP_RDI": {"address": "0x400686", "instructions": "pop rdi; ret"},
    "POP_RSI": {"address": "0x400687", "instructions": "pop rsi; ret"},
    "SYSCALL": {"address": "0x400688", "instructions": "syscall"}
}'''

result = ctf_rop_build_execve_chain(
    gadgets_json=gadgets_json,
    binsh_addr="0x601000",
    arch="x64"
)
```

#### `ctf_rop_find_gadgets`

Extract useful ROP gadgets from a binary file.

**Input Parameters:**
```python
binary_path: str       # Absolute path to binary file
arch: str = "x64"      # Target architecture: x64 or x86
```

**Returns:**
```python
{
    "success": bool,
    "gadget_count": int,              # Total gadgets found
    "gadgets": [
        {
            "address": str,           # Gadget address (hex)
            "instructions": str,      # Gadget instructions
            "type": str,              # Gadget type (POP, MOV, XOR, etc.)
            "registers": [str]        # Affected registers
        }
    ]
}
```

**Example Usage:**
```python
result = ctf_rop_find_gadgets(
    binary_path="/tmp/vuln_binary",
    arch="x64"
)
# Returns: {"gadget_count": 2847, "gadgets": [...]}
```

---

### 5. Web CTF Solver Tools (4 Tools)

#### `ctf_web_ssrf_discover`

Discover Server-Side Request Forgery (SSRF) vulnerability chains.

**Input Parameters:**
```python
target: str            # Base target URL (e.g., "http://example.com")
endpoints: str = ""    # Comma-separated endpoints (e.g., "/api/fetch,/proxy")
parameters: str = ""   # Comma-separated parameters (e.g., "url,link,fetch")
timeout: int = 30      # Request timeout in seconds
```

**Returns:**
```python
{
    "success": bool,           # SSRF chains found
    "chains_found": int,       # Number of exploitable chains
    "chains": [
        {
            "endpoint": str,           # Vulnerable endpoint
            "parameter": str,          # Parameter accepting URLs
            "protocol": str,           # Protocol tested (http, file, gopher, etc.)
            "access_level": str,       # None, metadata, internal, etc.
            "payload": str,            # Exploit payload
            "evidence": str            # Proof of exploitation
        }
    ]
}
```

**Example Usage:**
```python
result = ctf_web_ssrf_discover(
    target="http://localhost:3000",
    endpoints="/api/fetch,/image/download",
    parameters="url,imageUrl",
    timeout=30
)
```

#### `ctf_web_race_condition`

Exploit race condition vulnerabilities with concurrent requests.

**Input Parameters:**
```python
target: str            # Base target URL
endpoint: str          # Endpoint to target (e.g., "/api/transfer")
payload: str           # JSON string with request payload
concurrent: int = 100  # Number of concurrent requests
```

**Returns:**
```python
{
    "success": bool,           # Race condition exploited
    "requests_sent": int,      # Total requests sent
    "anomalies_detected": int, # Response anomalies found
    "flag": str,               # Flag if recovered
    "timing_analysis": {
        "average_response_time": float,
        "response_variance": float
    },
    "exploitation_details": str
}
```

**Example Usage:**
```python
result = ctf_web_race_condition(
    target="http://localhost:3000",
    endpoint="/api/transfer",
    payload='{"from": "attacker", "to": "admin", "amount": 1000}',
    concurrent=100
)
```

#### `ctf_web_prototype_pollution`

Scan for JavaScript prototype pollution vulnerabilities.

**Input Parameters:**
```python
target: str            # Base target URL
endpoints: str = ""    # Comma-separated endpoints (e.g., "/api/update,/settings")
```

**Returns:**
```python
{
    "success": bool,           # Vulnerabilities found
    "scans_performed": int,    # Number of scans
    "vulnerabilities": [
        {
            "endpoint": str,           # Vulnerable endpoint
            "parameter": str,          # Vulnerable parameter
            "payload": str,            # Exploit payload
            "affected_properties": [str],  # Object properties polluted
            "severity": str            # Critical, High, Medium, etc.
        }
    ]
}
```

**Example Usage:**
```python
result = ctf_web_prototype_pollution(
    target="http://localhost:3000",
    endpoints="/api/profile/update,/api/settings"
)
```

#### `ctf_web_jwt_attack`

Analyze JWT tokens and test for common vulnerabilities.

**Input Parameters:**
```python
token: str             # JWT token to analyze
target: str = ""       # Base target URL for testing (optional)
endpoint: str = ""     # API endpoint for token validation (optional)
```

**Returns:**
```python
{
    "success": bool,           # Analysis completed
    "token_valid": bool,       # Token is structurally valid
    "vulnerabilities": [
        {
            "type": str,       # Vulnerability type
            "severity": str,   # Critical, High, etc.
            "description": str,
            "forged_token": str  # Exploitable token
        }
    ],
    "payload_decoded": dict,   # Decoded JWT payload
    "header_decoded": dict,    # Decoded JWT header
    "signature_algorithm": str # Algorithm used
}
```

**Example Usage:**
```python
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
result = ctf_web_jwt_attack(
    token=token,
    target="http://localhost:3000",
    endpoint="/api/protected"
)
```

---

## Integration with AI Agents

### Claude API + MCP

```python
# Initialize Claude with MCP server
from anthropic import Anthropic

client = Anthropic()

response = client.messages.create(
    model="claude-opus-4-5-20251101",
    max_tokens=4096,
    tools=[
        {
            "name": "ctf_classify_challenge",
            "description": "Classify CTF challenge and recommend tools"
        },
        # ... other tools ...
    ],
    messages=[
        {
            "role": "user",
            "content": "I have an RSA challenge with these parameters: n=123456789, e=65537. Solve it."
        }
    ]
)
```

### OpenAI GPT-4 Integration

```python
# Use HexStrike MCP with OpenAI's tool calling
import subprocess
import json

# Start HexStrike MCP server
proc = subprocess.Popen(["python3", "hexstrike_mcp.py", "--server", "http://localhost:8888"])

# GPT-4 can now call tools through MCP interface
```

### GitHub Copilot

Copilot Chat supports MCP tools when configured:

1. Configure MCP in `.github/copilot/config.json`
2. Copilot can use tools like:
   ```
   @codebase Classify this CTF challenge and recommend solving tools
   @codebase Generate a format string ROP chain for this binary
   ```

---

## Common CTF Workflows

### RSA Challenge Workflow

```
1. ctf_classify_challenge(description)
   → Returns: category=CRYPTO, subtype=RSA

2. ctf_rsa_auto_attack(n, e, c)
   → Tries: fermat, wiener, factordb, small_e
   → Returns: flag if successful

3. If auto fails, try specific attacks:
   - ctf_rsa_wiener_attack() for large e
   - ctf_rsa_fermat_attack() for close primes
```

### Binary Exploitation Workflow

```
1. ctf_classify_challenge(binary_file)
   → Returns: category=PWN, subtype=format_string

2. ctf_rop_find_gadgets(binary)
   → Returns: list of available ROP gadgets

3. ctf_format_string_arbitrary_write(target_addr, value, offset)
   → Generate format string payload

4. ctf_rop_build_execve_chain(gadgets, binsh_addr)
   → Build complete exploitation chain
```

### Web Challenge Workflow

```
1. ctf_classify_challenge(url, description)
   → Returns: category=WEB, subtype=ssrf or race_condition

2. For SSRF:
   - ctf_web_ssrf_discover(target, endpoints)
   - Use discovered chains for exploitation

3. For Race Conditions:
   - ctf_web_race_condition(endpoint, payload, concurrent=100)

4. For JWT issues:
   - ctf_web_jwt_attack(token, target)
```

---

## Troubleshooting

### Tool Execution Fails

**Problem:** "Tool execution failed: Connection refused"

**Solution:**
```bash
# Ensure server is running
python3 hexstrike_server.py --debug

# In another terminal, start MCP client
python3 hexstrike_mcp.py --server http://localhost:8888 --debug
```

### RSA Attack Times Out

**Problem:** Fermat factorization takes too long

**Solution:**
```python
# Use smaller max_iterations for quick attempts
result = ctf_rsa_fermat_attack(n=n, max_iterations=1000)

# Or auto-attack with timeout
result = ctf_rsa_auto_attack(n=n, timeout=30)
```

### Format String Payload Fails

**Problem:** Generated payload doesn't work

**Checks:**
1. Verify offset is correct (use manual testing first)
2. Confirm architecture matches binary (x64 vs x86)
3. Check that target address is writable

```python
# Test with offset discovery first
result = ctf_format_string_arbitrary_write(
    address="0x601020",
    value="0x1",  # Small test value
    offset=6,
    arch="x64"
)
```

### ROP Gadgets Not Found

**Problem:** "Gadget count: 0"

**Solutions:**
1. Verify binary path is correct
2. Check binary is ELF format (not stripped heavily)
3. Try with fewer filters

```python
# Ensure binary exists
import os
assert os.path.exists(binary_path), f"Binary not found: {binary_path}"

# Try generic gadget finding
result = ctf_rop_find_gadgets(binary_path, arch="x64")
```

---

## Performance Tips

1. **Parallel Classification**: Classify multiple challenges concurrently
2. **Cache Results**: Store classification results to avoid re-analysis
3. **Timeout Tuning**: Adjust RSA attack timeouts based on modulus size
4. **Batch ROP Analysis**: Extract all gadgets once, reuse for multiple chains

---

## Security Notes

- These tools are designed for **authorized security testing only**
- Only use on CTF challenges or systems you own/have permission to test
- Some tools execute binary code (format strings, ROP chains) - test in isolated environments
- Never run generated payloads on untrusted systems

---

## API Reference

All tools are callable via REST API or MCP:

```bash
# REST API (direct server call)
curl -X POST http://localhost:8888/api/ctf/solvers/classify \
  -H "Content-Type: application/json" \
  -d '{"description": "RSA challenge", "files": ["key.pub"]}'

# MCP (via AI agent)
# Use tool name and parameters as shown in examples above
```

For more information, see `docs/ctf-workflows.md` for complete workflow examples.
