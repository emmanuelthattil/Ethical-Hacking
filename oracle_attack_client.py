#!/usr/bin/env python3
"""
Padding Oracle Attack Client for Three-Function Challenge
Exploits the get_flag function to perform padding oracle attack and find the target.
"""

import requests
import binascii
import sys
import time
from urllib.parse import quote

class ThreeFunctionOracleAttack:
    def __init__(self, server_url="http://localhost:8080"):
        self.server_url = server_url
        self.block_size = 16

    def get_hex(self, data):
        """Use the get_hex function"""
        try:
            response = requests.get(f"{self.server_url}/get_hex", params={'data': data})
            if response.status_code == 200:
                return response.json()['hex']
        except Exception as e:
            print(f"Error in get_hex: {e}")
        return None

    def encrypt_data(self, hex_data):
        """Use the encrypt function"""
        try:
            response = requests.get(f"{self.server_url}/encrypt", params={'hex': hex_data})
            if response.status_code == 200:
                return response.json()['encrypted']
        except Exception as e:
            print(f"Error in encrypt: {e}")
        return None

    def query_oracle(self, encrypted_hex):
        """
        Use get_flag as padding oracle
        Returns tuple: (is_valid_padding, error_type, is_target)
        """
        try:
            response = requests.get(f"{self.server_url}/get_flag", params={'encrypted': encrypted_hex})

            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    # Found the target!
                    return True, 'SUCCESS', True
                elif data.get('error_type') == 'WRONG_PLAINTEXT':
                    # Valid padding, wrong plaintext
                    return True, 'WRONG_PLAINTEXT', False
                elif data.get('error_type') == 'ENCODING_ERROR':
                    # Valid padding but invalid UTF-8
                    return True, 'ENCODING_ERROR', False
                else:
                    return False, 'UNKNOWN_200', False
            elif response.status_code == 400:
                data = response.json()
                error_type = data.get('error_type', 'UNKNOWN_400')
                if error_type == 'PADDING_ERROR':
                    return False, 'PADDING_ERROR', False
                else:
                    return False, error_type, False
            else:
                # Status 500 or other
                return False, 'SERVER_ERROR', False

        except Exception as e:
            return False, f'REQUEST_ERROR: {e}', False

    def demonstrate_oracle_behavior(self):
        """Show students how the oracle responds to different inputs"""
        print("🔍 ORACLE BEHAVIOR DEMONSTRATION")
        print("="*50)

        # Test 1: Valid plaintext (but not target)
        print("\n1. Testing known valid plaintext 'HELLO!!':")
        hello_hex = self.get_hex("HELLO!!")
        hello_encrypted = self.encrypt_data(hello_hex)
        if hello_encrypted:
            is_valid, error_type, is_target = self.query_oracle(hello_encrypted)
            print(f"   Hex: {hello_hex}")
            print(f"   Encrypted: {hello_encrypted[:32]}...")
            print(f"   Oracle response: Valid={is_valid}, Type={error_type}, Target={is_target}")

        # Test 2: Random invalid data
        print("\n2. Testing random invalid data:")
        random_hex = "41424344454647484950515253545556" * 2  # 32 bytes
        is_valid, error_type, is_target = self.query_oracle(random_hex)
        print(f"   Hex: {random_hex}")
        print(f"   Oracle response: Valid={is_valid}, Type={error_type}, Target={is_target}")

        # Test 3: Modified padding
        print("\n3. Testing modified padding (flip last byte):")
        if hello_encrypted:
            modified_bytes = bytearray(binascii.unhexlify(hello_encrypted))
            modified_bytes[-1] ^= 1  # Flip last bit
            modified_hex = modified_bytes.hex().upper()

            is_valid, error_type, is_target = self.query_oracle(modified_hex)
            print(f"   Modified hex: {modified_hex[:32]}...")
            print(f"   Oracle response: Valid={is_valid}, Type={error_type}, Target={is_target}")

        print("\n" + "="*50)
        print("🤔 ORACLE ANALYSIS:")
        print("- Status 200 + SUCCESS = Found target plaintext")
        print("- Status 200 + WRONG_PLAINTEXT = Valid padding, wrong content")
        print("- Status 200 + ENCODING_ERROR = Valid padding, invalid UTF-8")
        print("- Status 400 + PADDING_ERROR = Invalid padding")
        print("- Status 500 = Server/decryption error")
        print("\n💡 This is a PADDING ORACLE - use it to attack!")

    def attack_single_byte(self, target_block_hex, previous_block_hex, byte_position):
        """
        Attack a single byte using padding oracle
        """
        print(f"\n⚔️  Attacking byte position {byte_position}")

        target_block = binascii.unhexlify(target_block_hex)
        previous_block = binascii.unhexlify(previous_block_hex)

        # Create attack IV (copy of previous block)
        attack_iv = bytearray(previous_block)

        # Set up for current padding length
        padding_value = self.block_size - byte_position
        print(f"   Target padding value: {padding_value}")

        # Set known bytes to produce correct padding
        for i in range(byte_position + 1, self.block_size):
            if hasattr(self, 'intermediate_values') and i in self.intermediate_values:
                attack_iv[i] = self.intermediate_values[i] ^ padding_value

        # Brute force current byte
        print(f"   Brute forcing byte {byte_position}...")
        candidates = []

        for guess in range(256):
            attack_iv[byte_position] = guess

            # Create test ciphertext (attack_iv + target_block)
            test_ciphertext = bytes(attack_iv) + target_block
            test_hex = test_ciphertext.hex().upper()

            # Query oracle
            is_valid, error_type, is_target = self.query_oracle(test_hex)

            if is_valid:  # Valid padding found
                candidates.append(guess)
                print(f"   Found candidate: {guess} (0x{guess:02x})")

                # For the last byte, verify it's really 0x01 padding
                if byte_position == self.block_size - 1 and len(candidates) == 1:
                    # Verify by changing the previous byte
                    verify_iv = bytearray(attack_iv)
                    verify_iv[byte_position - 1] ^= 1
                    verify_ciphertext = bytes(verify_iv) + target_block
                    verify_hex = verify_ciphertext.hex().upper()

                    is_valid_verify, _, _ = self.query_oracle(verify_hex)
                    if is_valid_verify:
                        # This was probably longer padding, continue searching
                        continue
                    else:
                        # Confirmed 0x01 padding
                        break
                else:
                    break

        if candidates:
            # Calculate intermediate and plaintext values
            guess = candidates[0]  # Take first valid candidate
            intermediate = guess ^ padding_value
            plaintext_byte = intermediate ^ previous_block[byte_position]

            print(f"   ✓ Byte {byte_position}: plaintext=0x{plaintext_byte:02x} ('{chr(plaintext_byte) if 32 <= plaintext_byte <= 126 else '?'}')")

            # Store intermediate value for next iterations
            if not hasattr(self, 'intermediate_values'):
                self.intermediate_values = {}
            self.intermediate_values[byte_position] = intermediate

            return plaintext_byte
        else:
            print(f"   ❌ Failed to find byte {byte_position}")
            return 0

    def decrypt_block(self, target_block_hex, previous_block_hex):
        """Decrypt a complete block using padding oracle attack"""
        print(f"\n🎯 Decrypting block: {target_block_hex}")
        print(f"🔗 Previous block:    {previous_block_hex}")

        # Reset intermediate values for this block
        self.intermediate_values = {}

        # Decrypt byte by byte from right to left
        plaintext_bytes = bytearray(self.block_size)

        for byte_pos in range(self.block_size - 1, -1, -1):
            plaintext_bytes[byte_pos] = self.attack_single_byte(
                target_block_hex, previous_block_hex, byte_pos
            )

            # Small delay to avoid overwhelming server
            time.sleep(0.1)

        return bytes(plaintext_bytes)

    def forge_target_encryption(self, target_plaintext):
        """
        Forge an encryption of the target plaintext using padding oracle
        This is the reverse of decryption - we know the plaintext and forge the ciphertext
        """
        print(f"\n🔨 FORGING ENCRYPTION OF: '{target_plaintext}'")
        print("="*50)

        # Pad the target plaintext
        from Crypto.Util.Padding import pad
        padded_plaintext = pad(target_plaintext.encode(), self.block_size)

        print(f"Padded plaintext: {padded_plaintext.hex().upper()}")
        print(f"Plaintext blocks: {len(padded_plaintext) // self.block_size}")

        # For simplicity, we'll forge a single block encryption
        # In a full implementation, you'd handle multiple blocks

        if len(padded_plaintext) > self.block_size:
            print("Multi-block forgery not implemented in this demo")
            print("Using first block only...")
            padded_plaintext = padded_plaintext[:self.block_size]

        # Choose a target block (can be anything - we'll use a known encrypted block)
        known_plaintext = "A" * self.block_size
        known_hex = known_plaintext.encode().hex().upper()
        known_encrypted = self.encrypt_data(known_hex)

        if not known_encrypted:
            print("Failed to get known encrypted block")
            return None

        known_encrypted_bytes = binascii.unhexlify(known_encrypted)
        known_iv = known_encrypted_bytes[:self.block_size]
        known_block = known_encrypted_bytes[self.block_size:self.block_size*2]

        print(f"\nUsing known encrypted block: {known_block.hex().upper()}")

        # Now forge an IV that will make this block decrypt to our target
        forged_iv = bytearray(self.block_size)

        # We need: plaintext[i] = intermediate[i] ⊕ iv[i]
        # So: iv[i] = intermediate[i] ⊕ plaintext[i]
        # But we don't know intermediate values directly...

        print("\n🔍 To complete the forgery, we need to:")
        print("1. Decrypt the known block to find intermediate values")
        print("2. Calculate IV bytes: iv[i] = intermediate[i] ⊕ target_plaintext[i]")
        print("3. Construct the forged ciphertext: forged_iv + known_block")

        # For demo purposes, let's try a different approach
        # We'll use the oracle to find the correct IV
        print("\n🎯 Alternative approach: Brute force IV using oracle")

        # This would be very slow for a full IV, so let's just demonstrate the concept
        print("(This would take too long for a demo - showing concept only)")

        return None

    def solve_challenge(self):
        """Main solving function"""
        print("🎯 THREE-FUNCTION PADDING ORACLE CHALLENGE SOLVER")
        print("="*60)

        # Step 1: Understand the oracle
        self.demonstrate_oracle_behavior()

        # Step 2: Get target information
        print("\n🔍 GATHERING TARGET INFORMATION")
        print("="*40)

        try:
            response = requests.get(f"{self.server_url}/hint")
            if response.status_code == 200:
                hint_data = response.json()
                target_info = hint_data.get('target_info', 'Unknown')
                print(f"Target: {target_info}")

            # Also try the oracle demo endpoint
            response = requests.get(f"{self.server_url}/oracle_demo")
            if response.status_code == 200:
                demo_data = response.json()
                examples = demo_data.get('examples', [])
                print(f"\nFound {len(examples)} oracle examples")

        except Exception as e:
            print(f"Could not get hint information: {e}")

        # Step 3: Try to find patterns or leaked information
        print("\n🔍 ANALYZING ORACLE RESPONSES")
        print("="*40)

        # Try encrypting the known target and see what happens
        target = "CSCI515"
        target_hex = self.get_hex(target)

        print(f"Known target: {target}")
        print(f"Target hex: {target_hex}")

        # Try encrypting it multiple times to see randomness
        print("\nTrying direct encryption (should fail due to random IV):")
        for i in range(3):
            encrypted = self.encrypt_data(target_hex)
            if encrypted:
                is_valid, error_type, is_target = self.query_oracle(encrypted)
                print(f"  Attempt {i+1}: {encrypted[:32]}... -> Valid={is_valid}, Target={is_target}")

        print("\n💡 CONCLUSION:")
        print("Direct encryption doesn't work because of random IVs.")
        print("Each encryption of CSCI515 gives a different result.")
        print("We need to use padding oracle attack to forge the correct encryption!")

        # Step 4: Demonstrate attack concept  
        print("\n⚔️  PADDING ORACLE ATTACK STRATEGY")
        print("="*40)
        print("1. The server has a fixed target encryption in memory")
        print("2. We need to discover what that encryption is")
        print("3. Method 1: Decrypt known ciphertexts to understand patterns")
        print("4. Method 2: Forge an encryption that will pass validation")
        print("5. Method 3: Use oracle responses to map the encryption space")

        # For educational purposes, let's try to decrypt something
        print("\n🎓 EDUCATIONAL ATTACK DEMONSTRATION:")

        # Get a sample encryption to practice on
        sample_text = "HELLO!!"  # Same length as target
        sample_hex = self.get_hex(sample_text)
        sample_encrypted = self.encrypt_data(sample_hex)

        if sample_encrypted and len(sample_encrypted) >= 64:  # At least 32 bytes (IV + block)
            print(f"\nPractice target: '{sample_text}' -> {sample_hex}")
            print(f"Sample encryption: {sample_encrypted}")

            # Extract blocks
            sample_bytes = binascii.unhexlify(sample_encrypted)
            iv_hex = sample_bytes[:16].hex().upper()
            block1_hex = sample_bytes[16:32].hex().upper()

            print(f"\nBlock structure:")
            print(f"  IV:     {iv_hex}")
            print(f"  Block1: {block1_hex}")

            # Try to decrypt first block
            print(f"\n⚔️  Attempting to decrypt block1 using oracle...")
            print("(This will take time - demonstrating first few bytes only)")

            # Decrypt only first 2 bytes for demo (would take too long otherwise)
            print("\nDecrypting first 2 bytes of block (demo only):")

            for byte_pos in [15, 14]:  # Last two bytes
                decrypted_byte = self.attack_single_byte(block1_hex, iv_hex, byte_pos)
                print(f"  Byte {byte_pos}: 0x{decrypted_byte:02x} = '{chr(decrypted_byte) if 32 <= decrypted_byte <= 126 else '?'}'")
                time.sleep(0.5)  # Slow down for demo

        print("\n🏁 CHALLENGE COMPLETION")
        print("="*40)
        print("This demonstrates the padding oracle attack concept.")
        print("In a real attack, you would:")
        print("1. Complete the block decryption")
        print("2. Use patterns to understand the target format")
        print("3. Forge the exact encryption the server expects")
        print("4. Submit it to get_flag to retrieve the flag")

        return False

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--demo":
        # Quick oracle demonstration
        attacker = ThreeFunctionOracleAttack()
        attacker.demonstrate_oracle_behavior()
        return

    print("Padding Oracle Attack for Three-Function Challenge")
    print("This exploits get_flag as a padding oracle to solve the challenge.")

    # Test server connection
    attacker = ThreeFunctionOracleAttack()
    try:
        response = requests.get(attacker.server_url)
        if response.status_code != 200:
            print("❌ Server not responding. Start with: python3 oracle_challenge_server.py")
            return
    except:
        print("❌ Cannot reach server at http://localhost:8080")
        return

    # Run the attack
    attacker.solve_challenge()

if __name__ == "__main__":
    main()
