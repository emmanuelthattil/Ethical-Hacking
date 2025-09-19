#!/usr/bin/env python3
"""
Padding Oracle Challenge Server (Video-Style Interface)
Same three functions as the video, but requires padding oracle attack to solve.
Students can't just encrypt "CSCI515" directly - they must use oracle techniques.
"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import base64
import binascii
import hashlib
import time

app = Flask(__name__)

# Server configuration
SECRET_KEY = b'HiddenSecretKey!'  # 16 bytes - students don't know this
BLOCK_SIZE = 16
TARGET_PLAINTEXT = "CSCI515"  # This is what they need to discover
ENCRYPTED_TARGET = None  # Will be generated

def generate_target_encryption():
    """Generate the encrypted target that students need to find"""
    global ENCRYPTED_TARGET

    # Create a specific IV for consistent results
    # In real scenarios, this might be from intercepted traffic
    iv = hashlib.md5(b"CSCI515_challenge").digest()

    cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
    padded = pad(TARGET_PLAINTEXT.encode(), BLOCK_SIZE)
    ciphertext = cipher.encrypt(padded)

    ENCRYPTED_TARGET = (iv + ciphertext).hex().upper()
    return ENCRYPTED_TARGET

def encrypt_data_cbc(plaintext_hex):
    """Encrypt hex data using AES-CBC with PKCS7 padding"""
    try:
        plaintext_bytes = binascii.unhexlify(plaintext_hex)

        # Use random IV for regular encryption
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)

        padded = pad(plaintext_bytes, BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded)

        result = iv + ciphertext
        return result.hex().upper()

    except Exception as e:
        return None

def decrypt_and_check_target(ciphertext_hex):
    """
    Decrypt ciphertext and check if it matches TARGET_PLAINTEXT
    THIS IS THE PADDING ORACLE - Returns different responses based on padding validity
    """
    try:
        ciphertext_bytes = binascii.unhexlify(ciphertext_hex)

        if len(ciphertext_bytes) < 32:  # At least IV + one block
            return False, "invalid_length"

        # Extract IV and ciphertext
        iv = ciphertext_bytes[:BLOCK_SIZE]
        ciphertext = ciphertext_bytes[BLOCK_SIZE:]

        if len(ciphertext) % BLOCK_SIZE != 0:
            return False, "invalid_block_size"

        # Decrypt
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # Remove padding - VULNERABILITY: This reveals padding errors
        unpadded = unpad(decrypted, BLOCK_SIZE)

        # Check if it matches our target
        plaintext = unpadded.decode('utf-8')

        if plaintext == TARGET_PLAINTEXT:
            return True, "target_match"
        else:
            return False, "wrong_plaintext"

    except ValueError as e:
        # Padding error - THE ORACLE RESPONSE
        if "Invalid padding" in str(e) or "Padding is incorrect" in str(e):
            return False, "padding_error"
        return False, "decode_error"
    except UnicodeDecodeError:
        return False, "encoding_error"
    except Exception as e:
        return False, "general_error"

@app.route('/')
def index():
    return '''
    <h1>Cryptographic Challenge (Padding Oracle Version)</h1>
    <h2>Available Functions (Same as Video):</h2>
    <ul>
        <li><strong>GET /get_hex?data=&lt;string&gt;</strong> - Convert string to hex</li>
        <li><strong>GET /encrypt?hex=&lt;hex_data&gt;</strong> - Encrypt hex data</li>
        <li><strong>GET /get_flag?encrypted=&lt;hex_ciphertext&gt;</strong> - Check if decrypts to target</li>
    </ul>

    <h3>🎯 Challenge:</h3>
    <p>Find the encrypted value that decrypts to the secret target plaintext!</p>
    <p><strong>Twist:</strong> Direct encryption won't work - you need to use cryptographic attack techniques!</p>

    <h3>🔍 Hints:</h3>
    <ul>
        <li>The target is a course code (7 characters)</li>
        <li>Regular encryption gives different results each time</li>
        <li>Pay attention to different error responses in get_flag</li>
        <li>Some responses reveal more information than others...</li>
    </ul>
    '''

@app.route('/get_hex')
def get_hex():
    """Function 1: Convert string to hexadecimal (same as video)"""
    data = request.args.get('data', '')
    if not data:
        return jsonify({'error': 'Missing data parameter'}), 400

    hex_value = data.encode('utf-8').hex().upper()
    return jsonify({
        'input': data,
        'hex': hex_value
    })

@app.route('/encrypt')  
def encrypt():
    """
    Function 2: Encrypt hexadecimal data (same interface as video)
    BUT: Uses random IV each time - direct approach won't work!
    """
    hex_data = request.args.get('hex', '')
    if not hex_data:
        return jsonify({'error': 'Missing hex parameter'}), 400

    try:
        encrypted = encrypt_data_cbc(hex_data)
        if encrypted:
            return jsonify({
                'input_hex': hex_data,
                'encrypted': encrypted,
                'note': 'Uses random IV - result changes each time!'
            })
        else:
            return jsonify({'error': 'Encryption failed'}), 400
    except Exception as e:
        return jsonify({'error': 'Invalid hex data'}), 400

@app.route('/get_flag')
def get_flag():
    """
    Function 3: Check if encrypted data decrypts to target (same interface as video)  
    BUT: Acts as padding oracle with different responses
    """
    encrypted = request.args.get('encrypted', '')
    if not encrypted:
        return jsonify({'error': 'Missing encrypted parameter'}), 400

    # Add small delay to make timing attacks less obvious
    time.sleep(0.05)

    try:
        is_target, error_type = decrypt_and_check_target(encrypted)

        if is_target:
            # SUCCESS - they found the target!
            return jsonify({
                'status': 'success',
                'flag': 'CSCI515{padding_oracle_attack_master}',
                'message': 'Congratulations! You found the correct encrypted value!',
                'plaintext': TARGET_PLAINTEXT
            }), 200
        else:
            # Different error responses - THIS IS THE ORACLE
            if error_type == "padding_error":
                return jsonify({
                    'status': 'error',
                    'message': 'Decryption failed - invalid padding detected',
                    'error_type': 'PADDING_ERROR'
                }), 400
            elif error_type == "wrong_plaintext":
                return jsonify({
                    'status': 'error',
                    'message': 'Valid decryption but incorrect plaintext',
                    'error_type': 'WRONG_PLAINTEXT',
                    'hint': 'You decrypted something, but it\'s not the target!'
                }), 200
            elif error_type == "invalid_length":
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid ciphertext length',
                    'error_type': 'LENGTH_ERROR'
                }), 400
            elif error_type == "encoding_error":
                return jsonify({
                    'status': 'error',
                    'message': 'Decrypted data is not valid text',
                    'error_type': 'ENCODING_ERROR'
                }), 200
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Decryption processing failed',
                    'error_type': 'GENERAL_ERROR'
                }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Server error during decryption',
            'error_type': 'SERVER_ERROR'
        }), 500

@app.route('/hint')
def hint():
    """Provide hints for students who are stuck"""
    return jsonify({
        'target_info': 'The target is a 7-character course code: CSCI515',
        'approach': 'Direct encryption won\'t work due to random IVs',
        'oracle_hint': 'Different error responses in get_flag reveal information',
        'attack_strategy': 'Use padding oracle techniques to forge the correct encrypted value',
        'key_insight': 'You don\'t need to know the key - exploit the padding oracle!'
    })

@app.route('/oracle_demo')
def oracle_demo():
    """Demonstrate oracle behavior with example ciphertexts"""
    examples = []

    # Example 1: Valid ciphertext (but wrong plaintext)
    try:
        wrong_plaintext = "HELLO!!"  # 7 chars like target
        wrong_hex = wrong_plaintext.encode().hex().upper()
        wrong_encrypted = encrypt_data_cbc(wrong_hex)
        examples.append({
            'description': 'Valid encryption of "HELLO!!" (wrong plaintext)',
            'encrypted': wrong_encrypted,
            'expected_response': 'WRONG_PLAINTEXT (Status 200)'
        })
    except:
        pass

    # Example 2: Invalid padding
    try:
        # Create invalid padding by modifying last byte
        target_hex = TARGET_PLAINTEXT.encode().hex().upper()  
        valid_encrypted = encrypt_data_cbc(target_hex)
        invalid_bytes = bytearray(binascii.unhexlify(valid_encrypted))
        invalid_bytes[-1] ^= 1  # Flip last bit to break padding
        invalid_encrypted = invalid_bytes.hex().upper()

        examples.append({
            'description': 'Modified ciphertext with invalid padding',
            'encrypted': invalid_encrypted,
            'expected_response': 'PADDING_ERROR (Status 400)'
        })
    except:
        pass

    return jsonify({
        'message': 'Oracle behavior examples',
        'examples': examples,
        'explanation': 'Notice how different inputs produce different error types and status codes'
    })

if __name__ == '__main__':
    print("="*70)
    print("🔒 PADDING ORACLE CHALLENGE (Video-Style Interface)")
    print("="*70)
    print("Same three functions as the video:")
    print("  GET /get_hex     - Convert string to hex")
    print("  GET /encrypt     - Encrypt hex data")  
    print("  GET /get_flag    - Check if decrypts to target")
    print()
    print("🎯 Challenge: Find encrypted value that decrypts to secret target!")
    print("🔥 Twist: Direct approach won't work - you need padding oracle attack!")
    print()
    print(f"Target plaintext: {TARGET_PLAINTEXT}")
    print(f"Target hex: {TARGET_PLAINTEXT.encode().hex().upper()}")
    print()
    print("Server: http://localhost:8080")
    print("="*70)
    print("💡 KEY INSIGHT: get_flag acts as a padding oracle!")
    print("   Different error responses reveal cryptographic information.")
    print("   Use this to your advantage!")
    print("="*70)

    # Generate the target encryption
    target_encrypted = generate_target_encryption()
    print(f"🎯 Secret target encryption: {target_encrypted}")
    print("(Students must discover this through oracle attack)")
    print("="*70)

    app.run(host='0.0.0.0', port=8080, debug=False)
