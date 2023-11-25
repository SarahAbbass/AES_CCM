from Crypto.Cipher import AES
from Crypto.Util import Counter
from Encryption import key, ciphertext_blocks, counter_blocks

def ctr_decrypt(ciphertext_blocks, counter_blocks, key):

    # Initialize Counter mode with the counter blocks
    ctr = Counter.new(128, initial_value=int.from_bytes(counter_blocks[0], byteorder='big'))

    # Create a new AES cipher in CTR mode
    ctr_cipher = AES.new(key, AES.MODE_CTR, counter=ctr)

    # Decrypt each block of the ciphertext
    decrypted_blocks = [ctr_cipher.decrypt(block) for block in ciphertext_blocks]

    # Convert the decrypted blocks to bytes
    decrypted_text = b''.join(decrypted_blocks)

    return decrypted_text

decrypted_text = ctr_decrypt(ciphertext_blocks, counter_blocks, key)
print("Decrypted Text:", decrypted_text)
