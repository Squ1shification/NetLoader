#!/usr/bin/env python3
"""Generate XOR-encrypted byte arrays for C# string constants.

Usage: python3 encrypt_string.py <string> [key_hex]
Default key: 0x4B

The output is a C# byte array declaration ready to paste into Program.cs.
The decryption uses a rotating key: byte[i] ^ (key + i)
"""
import sys

def encrypt(plaintext, key=0x4B):
    enc = []
    for i, ch in enumerate(plaintext):
        enc.append(ord(ch) ^ ((key + i) & 0xFF))
    return enc

def to_cs_array(name, data):
    hex_vals = ", ".join(f"0x{b:02X}" for b in data)
    return f"private static byte[] {name} = new byte[] {{ {hex_vals} }};"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <string> [key_hex] [var_name]")
        sys.exit(1)

    plaintext = sys.argv[1]
    key = int(sys.argv[2], 16) if len(sys.argv) > 2 else 0x4B
    var_name = sys.argv[3] if len(sys.argv) > 3 else "_sX"

    encrypted = encrypt(plaintext, key)
    print(f'// "{plaintext}"')
    print(to_cs_array(var_name, encrypted))
    print()

    # Verify round-trip
    decrypted = ""
    for i, b in enumerate(encrypted):
        decrypted += chr(b ^ ((key + i) & 0xFF))
    assert decrypted == plaintext, f"Round-trip failed: got '{decrypted}'"
    print(f"// Verified: decrypts back to \"{plaintext}\"")
