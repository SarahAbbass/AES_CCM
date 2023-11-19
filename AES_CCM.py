from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
import binascii
import AES_CBR

# Key generation
key = b'Sixteen byte key'
nonce = get_random_bytes(13)  # 13-byte nonce
message = b"Hello, AES-CCM!"  # Your input message

# AES-CTR Encryption
ctr_cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
ciphertext = ctr_cipher.encrypt(pad(message, AES.block_size))

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
