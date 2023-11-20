from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import binascii
import AES_CBR

# Key generation
key = b'Sixteen byte key'
nonce = get_random_bytes(13)  # 13-byte nonce
message = b"Hello, AES-CCM!"  # Your input message

# AES-CTR Encryption
def aes_encrypt_block(block, key):
    # This function encrypts a single AES block
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(block)
def aes_ctr_encrypt(plaintext, key, nonce):
    block_size = AES.block_size
    num_blocks = (len(plaintext) + block_size - 1) // block_size

    # Initialize counters
    counters = [nonce + (i).to_bytes(8, byteorder='big')[:block_size - len(nonce)] for i in range(num_blocks)]

    # Encrypt each block and XOR with plaintext
    ciphertext = b''
    for i in range(num_blocks):
        keystream_block = aes_encrypt_block(counters[i], key)
        plaintext_block = plaintext[i * block_size: (i + 1) * block_size]
        ciphertext_block = bytes(x ^ y for x, y in zip(plaintext_block, keystream_block))
        ciphertext += ciphertext_block
    return ciphertext

ciphertext = aes_ctr_encrypt(pad(message, AES.block_size), key, nonce)

# AES-CBC-MAC
cbc_mac_cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))
iv = bytes(16)  # 16 bytes of zeros
mac_tag = AES_CBR.custom_aes_cbc_mac(key, ciphertext, iv)

# Output in hexadecimal
key_hex = binascii.hexlify(key)
nonce_hex = binascii.hexlify(nonce)
ciphertext_hex = binascii.hexlify(ciphertext)

# Print the results
print("Key (hex):", key_hex.decode('utf-8'))
print("Nonce (hex):", nonce_hex.decode('utf-8'))
print("Ciphertext (hex):", ciphertext_hex.decode('utf-8'))
print("MAC Tag (hex):", binascii.hexlify(mac_tag).decode('utf-8'))

# Decryption (reverse the process)
ctr_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
decrypted_message = unpad(ctr_cipher.decrypt(ciphertext), AES.block_size)

print("Decrypted Message:", decrypted_message.decode('utf-8'))
