#!/usr/bin/env python3
import sys
import re

def caesar_cipher(text, displacement):
    """
    Encrypts text using the Caesar cipher algorithm.
    Only processes English alphabet letters (a-z, A-Z).
    Non-alphabet characters remain unchanged.
    """
    result = []
    
    for char in text:
        if char.isalpha():
            # Determine if uppercase or lowercase
            base = ord('A') if char.isupper() else ord('a')
            # Apply displacement and keep within alphabet range
            new_char = chr((ord(char) - base + displacement) % 26 + base)
            result.append(new_char)
        else:
            # Keep non-alphabet characters unchanged
            result.append(char)
    
    return ''.join(result)

def main():
    # Check command line arguments
    if len(sys.argv) != 3:
        print("Usage: sudo python3 script.py \"text to encrypt\" displacement")
        print("Example: sudo python3 script.py \"criptografia y seguridad en redes\" 9")
        sys.exit(1)
    
    # Get text and displacement from command line
    text = sys.argv[1]
    
    try:
        displacement = int(sys.argv[2])
    except ValueError:
        print("Error: Displacement must be an integer")
        sys.exit(1)
    
    # Handle negative displacement (decryption)
    displacement = displacement % 26
    
    # Encrypt the text
    encrypted_text = caesar_cipher(text, displacement)
    
    # Print the result
    print(f"Original text: {text}")
    print(f"Displacement: {displacement}")
    print(f"Encrypted text: {encrypted_text}")

if __name__ == "__main__":
    main()