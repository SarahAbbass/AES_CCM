from Crypto.Cipher import AES
from Crypto.Hash import CMAC
from Crypto.Util.strxor import strxor
from Encryption import aes_encrypt_cbc, aes_encrypt_ctr, key, nonce, counter_blocks, final_ciphertext

def aes_decrypt_ctr(key, ciphertext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(ciphertext)

def cmac_verification(key, nonce, blocks, encrypted_tag):
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
    recalculated_encrypted_tag = aes_encrypt_ctr(key, Ctr0)
    recalculated_encrypted_tag = CMAC.new(tag, ciphermod=AES).digest()
    recalculated_encrypted_tag = strxor(recalculated_encrypted_tag, tag)

    # Step 5: Verify the Encrypted Tag
    if recalculated_encrypted_tag == encrypted_tag:
        return True
    else:
        return False

# Step 1: Separate Ciphertext Blocks and Encrypted Tag
ciphertext = final_ciphertext[:-16]
block_size = len(ciphertext) // 4
cipher_blocks = [ciphertext[i:i + block_size] for i in range(0, len(ciphertext), block_size)]
received_encrypted_tag = final_ciphertext[-16:]

# Step 2: Decrypt Ciphertext Blocks
decrypted_blocks = []
for ctr, cipher_block in zip(counter_blocks[1:], cipher_blocks):
    decrypt = aes_decrypt_ctr(key, ctr) 
    xoring = strxor(decrypt, cipher_block)
    decrypted_blocks.append(xoring)

# Step 3: Verify CMAC
verification_result = cmac_verification(key, nonce, decrypted_blocks, received_encrypted_tag)

# Step 4: Print results
print("Decrypted Blocks:", [block.hex() for block in decrypted_blocks])
print("CMAC Verification Result:", verification_result)
