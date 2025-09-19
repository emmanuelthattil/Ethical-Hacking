# Padding Oracle Challenge - Three Function Interface

## Perfect! Same Interface, Oracle Attack Required

This is exactly what you wanted - the **same three functions** as the video (`get_hex`, `encrypt`, `get_flag`), but students **must use padding oracle attack techniques** to solve it instead of the direct approach.

## The Challenge Setup

### Same Three Functions (As in Video)
1. **`GET /get_hex?data=<string>`** - Convert string to hex
2. **`GET /encrypt?hex=<hex_data>`** - Encrypt hex data  
3. **`GET /get_flag?encrypted=<hex_ciphertext>`** - Check if decrypts to target

### The Twist That Requires Oracle Attack
- **Random IVs**: `encrypt` uses random IV each time, so direct approach fails
- **Fixed Target**: Server has one specific encrypted value that gives the flag
- **Oracle Responses**: `get_flag` returns different errors revealing padding information

## Why Direct Approach Fails

### Video's Direct Method:
```bash
# This would work in the video
curl "http://localhost:8080/get_hex?data=CSCI515"     # Get hex
curl "http://localhost:8080/encrypt?hex=43534349353135"  # Encrypt it
curl "http://localhost:8080/get_flag?encrypted=<result>"  # Get flag
```

### Why It Fails Here:
1. **Random IVs**: Each call to `encrypt` produces different results
2. **Fixed Target**: Server expects ONE specific encrypted value
3. **Different Each Time**: `encrypt("CSCI515")` gives different output each call

## The Oracle Attack Solution

### Step 1: Recognize the Oracle
```bash
python3 oracle_challenge_server.py  # Start server
python3 oracle_attack_client.py --demo  # See oracle behavior
```

**Oracle Responses:**
- `Status 200 + SUCCESS` → Found the target!
- `Status 200 + WRONG_PLAINTEXT` → Valid padding, wrong content  
- `Status 400 + PADDING_ERROR` → Invalid padding
- `Status 500` → Server/decryption error

### Step 2: Understand the Problem
```bash
# Try direct approach - it fails!
curl "http://localhost:8080/get_hex?data=CSCI515"
# Returns: {"hex": "43534349353135"}

curl "http://localhost:8080/encrypt?hex=43534349353135"  
# Returns different result each time due to random IV!

# Each result fails when tested:
curl "http://localhost:8080/get_flag?encrypted=<different_each_time>"
# Returns: {"error_type": "WRONG_PLAINTEXT"} - valid decryption but not the target
```

### Step 3: Use Oracle Attack
```bash
python3 oracle_attack_client.py
```

**Attack Strategy:**
1. **Exploit the Oracle**: Use different error responses to gain information
2. **Map the Space**: Understand how padding affects responses
3. **Forge Target**: Create the specific encrypted value the server expects
4. **Get Flag**: Submit the correct encrypted value

## Detailed Attack Process

### Oracle Analysis
The `get_flag` function acts as a padding oracle:

```python
# Different responses reveal information:
def query_oracle(encrypted_hex):
    response = requests.get(f"/get_flag?encrypted={encrypted_hex}")
    
    if response.status_code == 200:
        if "success" in response.json():
            return "TARGET_FOUND"  # This is what we want!
        elif "WRONG_PLAINTEXT" in response.json():
            return "VALID_PADDING_WRONG_CONTENT"
        elif "ENCODING_ERROR" in response.json():
            return "VALID_PADDING_INVALID_UTF8"
    elif response.status_code == 400:
        return "INVALID_PADDING"  # Oracle response!
    else:
        return "SERVER_ERROR"
```

### Attack Implementation
Students must implement:

1. **Oracle Logic**: Distinguish valid from invalid padding
2. **Bit Manipulation**: Modify ciphertext systematically  
3. **Block Attack**: Decrypt or forge block by block
4. **Target Discovery**: Find the specific encryption that gives the flag

## Quick Start Guide

### Method 1: Automated Learning
```bash
# Start the challenge server
python3 oracle_challenge_server.py

# Run the educational attack demonstration  
python3 oracle_attack_client.py
```

### Method 2: Manual Discovery
```bash
# Start server
python3 oracle_challenge_server.py

# Manual testing
curl "http://localhost:8080/"                           # See challenge
curl "http://localhost:8080/hint"                       # Get hints
curl "http://localhost:8080/oracle_demo"                # See oracle examples

# Try direct approach (will fail)
curl "http://localhost:8080/get_hex?data=CSCI515"
curl "http://localhost:8080/encrypt?hex=43534349353135"
curl "http://localhost:8080/get_flag?encrypted=<result>"

# Analyze oracle behavior
curl "http://localhost:8080/get_flag?encrypted=4142434445464748495051525354555641424344454647484950515253545556"
curl "http://localhost:8080/get_flag?encrypted=1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF"
```

### Method 3: Real Attack Implementation
```bash
# Study the oracle responses
# Implement your own attack algorithm
# Use bit manipulation to exploit the padding oracle
# Forge the correct encrypted value
```

## Key Learning Points

### Why This is More Realistic

1. **No Direct Solution**: Can't just encrypt and submit
2. **Oracle Discovery**: Must identify the vulnerability yourself  
3. **Attack Implementation**: Must understand and code the attack
4. **Cryptographic Math**: Must apply XOR operations correctly

### Skills Developed

1. **Oracle Recognition**: Identify information disclosure vulnerabilities
2. **Cryptanalysis**: Use mathematical attacks against encryption
3. **Bit Manipulation**: Understand how ciphertext modifications affect plaintext
4. **Attack Persistence**: Work through complex multi-step attacks

## Success Criteria

### You've completed the challenge when:
1. ✅ Recognized that direct approach fails due to random IVs
2. ✅ Identified the padding oracle in `get_flag` responses
3. ✅ Understood how to exploit the oracle for information
4. ✅ Successfully found or forged the target encrypted value  
5. ✅ Retrieved the flag: `CSCI515{padding_oracle_attack_master}`

## Files Summary

| File | Purpose |
|------|---------|
| `oracle_challenge_server.py` | Server with 3 functions + padding oracle |
| `oracle_attack_client.py` | Educational attack demonstration |
| `requirements.txt` | Python dependencies |

## The Perfect Balance

This gives you exactly what you wanted:
- **Same interface** as the video (3 simple functions)
- **Real cryptographic challenge** that requires attack techniques
- **Educational progression** from simple to complex
- **No easy shortcuts** - must understand the attack

Students will try the direct approach from the video, discover it doesn't work, then must learn padding oracle attack techniques to solve the challenge. This teaches both the basic concepts AND the advanced attack methods!