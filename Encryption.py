from Crypto.Cipher import AES
from Crypto.Util.strxor import strxor
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Random import get_random_bytes
from Crypto.Hash import CMAC

def aes_encrypt_cbc(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def aes_encrypt_ctr(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def generate_ctr_blocks(nonce, num_blocks):
    ctr_blocks = [nonce]
    for i in range(1, num_blocks):
        ctr_block = long_to_bytes(bytes_to_long(nonce) + i)
        ctr_blocks.append(ctr_block)
    return ctr_blocks

def cmac_algorithm(key, nonce, blocks):
    # Step 1: Initialize Y0
    Y0 = aes_encrypt_cbc(key, nonce)

    # Step 2: Calculate Y1 to Y4
    Y_values = [Y0]
    for i in range(1, len(blocks) + 1):
        Bi = blocks[i - 1]
        Yi = aes_encrypt_cbc(key, strxor(Bi, Y_values[i - 1]))
        Y_values.append(Yi)

    # Step 3: Calculate the final tag T = MSBlen(Y4)
    tag = CMAC.new(Y_values[4], ciphermod=AES).digest()

    # Step 4: Calculate Encrypted_Tag
    Ctr0 = nonce  # Ctr0 is the nonce
    Encrypted_Tag = aes_encrypt_ctr(key, Ctr0)
    Encrypted_Tag = CMAC.new(tag, ciphermod=AES).digest()
    Encrypted_Tag = strxor(Encrypted_Tag, tag)  

    return Encrypted_Tag

# Example usage:
key = b'\x01' * 16   #get_random_bytes(16)
nonce = b'\x02' * 16   #get_random_bytes(16)
plaintext_blocks = [b'\x03' * 16, b'\x04' * 16, b'\x05' * 16, b'\x06' * 16]   #[get_random_bytes(16) for _ in range(4)]

# Step 1: Generate Counter Blocks
counter_blocks = generate_ctr_blocks(nonce, len(plaintext_blocks) + 1)

# Step 2: Encrypt Plaintext Blocks
ciphertext_blocks = [strxor(aes_encrypt_ctr(key, ctr), plaintext) for ctr, plaintext in zip(counter_blocks[1:], plaintext_blocks)]

# Step 3: Perform CMAC Algorithm
encrypted_tag = cmac_algorithm(key, nonce, plaintext_blocks)

# Step 4: Concatenate Ciphertext Blocks and Encrypted Tag
final_ciphertext = b"".join(ciphertext_blocks) + encrypted_tag

# Print results
print("Key:", key.hex())
print("Nonce:", nonce.hex())
print("Plaintext Blocks:", [block.hex() for block in plaintext_blocks])
print("Counter Blocks:", [block.hex() for block in counter_blocks])
print("Ciphertext Blocks:", [block.hex() for block in ciphertext_blocks])
print("Encrypted Tag:", encrypted_tag.hex())
print("Final Ciphertext:", final_ciphertext.hex())
