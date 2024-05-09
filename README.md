

# AES CBC Mode Encryption and Decryption

This Python script provides functionality for encrypting and decrypting text using the AES encryption standard in CBC (Cipher Block Chaining) mode with PKCS7 padding.

## Dependencies

The script depends on the `cryptography` library. Ensure you have this library installed in your Python environment. You can install it using pip:

```bash
pip install cryptography
```

## Usage

The script defines two main functions: `AESCBC_ECB_encrypt` and `AESCBC_ECB_decrypt`. These functions allow you to encrypt plaintext and decrypt ciphertext, respectively.

### Functions

- **`AESCBC_ECB_encrypt(key, nonce, plaintext)`**:
  - **`key`**: A hexadecimal string representing the encryption key (must be 16, 24, or 32 bytes long for AES-128, AES-192, or AES-256, respectively).
  - **`nonce`**: A hexadecimal string used as the initialization vector; for AES-CBC, it should be 16 bytes long.
  - **`plaintext`**: The text string that you want to encrypt.
  - **Returns**: A string that concatenates the IV and the encrypted data, both encoded as hexadecimal.

- **`AESCBC_ECB_decrypt(key, nonce, cipher_data)`**:
  - **`key`**: A hexadecimal string representing the encryption key.
  - **`nonce`**: A hexadecimal string used as the initialization vector.
  - **`cipher_data`**: A hexadecimal string containing the IV followed by the encrypted data.
  - **Returns**: The decrypted text as a UTF-8 string, or an error message if decryption fails.

### Example Code

```python
key = "your_hexadecimal_key_here"
nonce = "your_hexadecimal_nonce_here"

plaintext = "Hello, how are you!"

# Encrypt the plaintext
cipher_data = AESCBC_ECB_encrypt(key, nonce, plaintext)
print("Cipher Data:", cipher_data)

# Decrypt the ciphertext
decrypted_text = AESCBC_ECB_decrypt(key, nonce, cipher_data)
print("Decrypted Plaintext:", decrypted_text)
```

## Important Notes

- Ensure that the key and nonce are provided as hexadecimal strings and are of the correct length.
- The script uses random IV generation for encryption, so the nonce parameter in the `AESCBC_ECB_encrypt` function is not used and can be passed as any dummy value.
- The script is designed for educational purposes and may require modifications for production use, especially concerning error handling and security best practices.

---

