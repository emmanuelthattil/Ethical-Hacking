#!/usr/bin/env python3
"""
Black Box Cryptographic Challenge Server
Similar to the approach shown in the instructional video.
Students interact with this as a black box through API endpoints.
"""

from flask import Flask, request, jsonify
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import base64
import hashlib

app = Flask(__name__)

# Server configuration (hidden from students)
SECRET_KEY = b'MySecretKey12345'  # 16 bytes for AES-128
BLOCK_SIZE = 16
TARGET_PLAINTEXT = b"CSCI515"  # What students need to discover
FLAG = "flag{padding_oracle_master_2025}"

def encrypt_data_cbc(plaintext_hex):
    """Encrypt hex data using AES-CBC with PKCS7 padding"""
    try:
        # Convert hex to bytes
        plaintext_bytes = binascii.unhexlify(plaintext_hex)

        # Generate random IV
        iv = get_random_bytes(BLOCK_SIZE)
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)

        # Pad and encrypt
        padded = pad(plaintext_bytes, BLOCK_SIZE)
        ciphertext = cipher.encrypt(padded)

        # Return IV + ciphertext as hex
        result = iv + ciphertext
        return result.hex().upper()

    except Exception as e:
        return None

def decrypt_and_validate(ciphertext_hex):
    """
    Decrypt ciphertext and check if it matches TARGET_PLAINTEXT
    This is the vulnerable function - acts as a padding oracle
    """
    try:
        # Convert hex to bytes
        ciphertext_bytes = binascii.unhexlify(ciphertext_hex)

        # Extract IV and ciphertext
        iv = ciphertext_bytes[:BLOCK_SIZE]
        ciphertext = ciphertext_bytes[BLOCK_SIZE:]

        # Decrypt
        cipher = AES.new(SECRET_KEY, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ciphertext)

        # Remove padding - THIS IS THE ORACLE VULNERABILITY
        unpadded = unpad(decrypted, BLOCK_SIZE)

        # Check if matches target
        if unpadded == TARGET_PLAINTEXT:
            return True, "success"
        else:
            return False, "invalid_plaintext"

    except ValueError as e:
        # Padding error - THIS IS THE ORACLE RESPONSE
        if "Invalid padding" in str(e) or "Padding is incorrect" in str(e):
            return False, "padding_error"
        return False, "decryption_error"
    except Exception as e:
        return False, "general_error"

@app.route('/')
def index():
    return '''
    <h1>Black Box Cryptographic Challenge</h1>
    <h2>Available Functions:</h2>
    <ul>
        <li><strong>GET /get_hex?data=&lt;string&gt;</strong> - Convert string to hex</li>
        <li><strong>GET /encrypt?hex=&lt;hex_data&gt;</strong> - Encrypt hex data (AES-CBC)</li>
        <li><strong>GET /get_flag?encrypted=&lt;hex_ciphertext&gt;</strong> - Check if decryption matches target</li>
    </ul>
    <p><em>Your goal: Find the encrypted value that decrypts to the target plaintext to get the flag.</em></p>
    '''

@app.route('/get_hex')
def get_hex():
    """Function 1: Convert string to hexadecimal"""
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
    """Function 2: Encrypt hexadecimal data using AES-CBC"""
    hex_data = request.args.get('hex', '')
    if not hex_data:
        return jsonify({'error': 'Missing hex parameter'}), 400

    try:
        encrypted = encrypt_data_cbc(hex_data)
        if encrypted:
            return jsonify({
                'input_hex': hex_data,
                'encrypted': encrypted
            })
        else:
            return jsonify({'error': 'Encryption failed'}), 400
    except Exception as e:
        return jsonify({'error': 'Invalid hex data'}), 400

@app.route('/get_flag')
def get_flag():
    """
    Function 3: Check if encrypted data decrypts to target plaintext
    THIS IS THE PADDING ORACLE - Returns different responses based on padding validity
    """
    encrypted = request.args.get('encrypted', '')
    if not encrypted:
        return jsonify({'error': 'Missing encrypted parameter'}), 400

    try:
        is_valid, error_type = decrypt_and_validate(encrypted)

        if is_valid:
            # Success - correct target plaintext found
            return jsonify({
                'status': 'success',
                'flag': FLAG,
                'message': 'Congratulations! You found the correct encrypted value.'
            })
        else:
            # Different error messages reveal information - THIS IS THE ORACLE
            if error_type == "padding_error":
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid padding detected',
                    'error_code': 'PADDING_ERROR'
                }), 400
            elif error_type == "invalid_plaintext":
                return jsonify({
                    'status': 'error', 
                    'message': 'Valid decryption but wrong plaintext',
                    'error_code': 'WRONG_PLAINTEXT'
                }), 200  # Note: 200 status but different message
            else:
                return jsonify({
                    'status': 'error',
                    'message': 'Decryption failed',
                    'error_code': 'DECRYPT_ERROR'
                }), 500

    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': 'Server error during processing',
            'error_code': 'SERVER_ERROR'
        }), 500

@app.route('/hint')
def hint():
    """Provide a hint for students"""
    return jsonify({
        'hint': 'The target plaintext is "CSCI515". Find its encrypted value!',
        'approach': 'Try encrypting different values and analyzing the responses from get_flag',
        'oracle_tip': 'Pay attention to different error messages - they reveal information about padding validity'
    })

if __name__ == '__main__':
    print("="*60)
    print("BLACK BOX CRYPTOGRAPHIC CHALLENGE SERVER")
    print("="*60)
    print(f"Server running on: http://localhost:8080")
    print(f"Target plaintext: {TARGET_PLAINTEXT.decode()}")
    print(f"Target hex: {TARGET_PLAINTEXT.hex().upper()}")
    print("="*60)
    print("VULNERABILITY: This server acts as a padding oracle!")
    print("Different error responses reveal padding validity.")
    print("="*60)

    app.run(host='0.0.0.0', port=8080, debug=False)
