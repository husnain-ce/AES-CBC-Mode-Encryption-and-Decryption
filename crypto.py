from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii
import os

def AESCBC_ECB_encrypt(key, nonce, plaintext):
    try:
        # Convert hex strings to bytes
        key_bytes = binascii.unhexlify(key)
        nonce_bytes = binascii.unhexlify(nonce)
        
        # Generate a random IV (Initialization Vector) for AES-CBC
        iv = os.urandom(16)
        
        # Initialize AES cipher in CBC mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
        encryptor = cipher.encryptor()
        
        # PKCS7 padding: pad plaintext to multiple of block size
        block_size = 16
        padding_length = block_size - len(plaintext) % block_size
        padded_plaintext = plaintext.encode('utf-8') + bytes([padding_length] * padding_length)
        
        # Encrypt padded plaintext
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Return IV + Ciphertext
        return binascii.hexlify(iv).decode('utf-8') + binascii.hexlify(ciphertext).decode('utf-8')
    except binascii.Error:
        return "Invalid hexadecimal string"

def AESCBC_ECB_decrypt(key, nonce, cipher_data):
    try:
        # Convert hex strings to bytes
        key_bytes = binascii.unhexlify(key)
        nonce_bytes = binascii.unhexlify(nonce)
        cipher_data_bytes = binascii.unhexlify(cipher_data)
        
        # Extract IV (nonce) and ciphertext blocks
        iv = cipher_data_bytes[:16]
        ciphertext = cipher_data_bytes[16:]
        
        # Initialize AES cipher in CBC mode
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv), backend=backend)
        decryptor = cipher.decryptor()
        
        # Decrypt ciphertext
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # PKCS7 padding removal
        pad_length = plaintext[-1]
        plaintext = plaintext[:-pad_length]
        
        # Decode plaintext from bytes to UTF-8
        return plaintext.decode('utf-8')
    except binascii.Error:
        return "Invalid hexadecimal string"

# Example usage
if __name__ == "__main__":
  
    key = "f95a00c0b178acb6c24a85146024146c1bb51d26d93182394228742f58ead6d1"
    nonce = "e0751dcbafd5612e14013c23ac20600f"
    
    plaintext = "Hello How are you!"
    
    cipher_data = AESCBC_ECB_encrypt(key, nonce, plaintext)
    print("Chipher Data " + str(cipher_data))
    
    plaintext = AESCBC_ECB_decrypt(key, nonce, cipher_data)
    print("Decrypted Plaintext:", plaintext)
