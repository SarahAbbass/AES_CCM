def custom_aes_cbc_mac(key, plaintext, iv):
    # This is a placeholder function and does not implement AES encryption
    # It only mimics the structure of AES CBC mode encryption for educational purposes

    # Placeholder for the actual AES encryption steps
    def simple_aes_encrypt(block, key):
        # This should be replaced with actual AES encryption
        return bytes(a ^ b for a, b in zip(block, key))

    # Initialization Vector
    previous_block = iv
    encrypted_blocks = []

    # Split the plaintext into 16-byte blocks
    block_size = 16
    blocks = [plaintext[i:i + block_size] for i in range(0, len(plaintext), block_size)]

    # Encrypt each block
    for block in blocks:
        # XOR the current block with the previous encrypted block
        block = bytes(a ^ b for a, b in zip(block, previous_block))

        # Encrypt the block (using a placeholder encryption function)
        encrypted_block = simple_aes_encrypt(block, key)
        encrypted_blocks.append(encrypted_block)

        # Update the previous block
        previous_block = encrypted_block

    # The MAC tag is the last encrypted block
    mac_tag = encrypted_blocks[-1]
    return mac_tag

