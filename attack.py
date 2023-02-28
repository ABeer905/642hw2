# /usr/bin/env python3

# CS 642 University of Wisconsin
#
# usage: python3 attack.py ciphertext
# Outputs a modified ciphertext and tag

import sys
import hashlib

# Grab ciphertext from first argument
ciphertextWithTag = bytes.fromhex(sys.argv[1])

if len(ciphertextWithTag) < 16+16+32:
  print("Ciphertext is too short!")
  sys.exit(0)

iv = ciphertextWithTag[:16]
ciphertext = ciphertextWithTag[:len(ciphertextWithTag)-32]
tag = ciphertextWithTag[len(ciphertextWithTag)-32:]

# To modify 12 to 92 we need to modify the 1 which is the 11th byte.
# In CBC mode the first 16 byte block is xor-ed with the IV meaning
# that the 11th index of the IV can be modified without impacting the
# rest of the blocks.

# Since 1 is plaintext 0x31 and 9 is 0x39 we can add 0x08
# to 0x31 to change 1 to 9. In some cases the cipher text
# will overflow when 0x08 is added so in this case we 
# subtract 8 instead.
# LSB < 8 -> add 8, lsb >= 8  -> minus 8 
new_byte = iv[11] + 8 if iv[11] % 16 < 8 else iv[11] - 8
iv = iv[:11] + new_byte.to_bytes(1, 'big') + iv[12:]

new_message = \
"""AMOUNT: $  92.99
Originating Acct Holder: Alexa
Orgininating Acct #98166-20633

I authorized the above amount to be transferred to the account #51779-31226 
held by a Wisc student at the National Bank of the Cayman Islands.
"""

#UPDATE TAG
tag = hashlib.sha256(new_message.encode()).hexdigest()

print(iv.hex() + ciphertext[16:].hex() + tag)
