from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
import base64
import time
import tracemalloc

# Function to encrypt plaintext using Blowfish
def encrypt_blowfish(key, plaintext):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # Using ECB mode
    padded_text = pad(plaintext.encode(), Blowfish.block_size)
    encrypted_bytes = cipher.encrypt(padded_text)
    encrypted_base64 = base64.b64encode(encrypted_bytes).decode()
    return encrypted_base64

# Function to decrypt ciphertext using Blowfish
def decrypt_blowfish(key, ciphertext):
    cipher = Blowfish.new(key, Blowfish.MODE_ECB)  # Using ECB mode
    encrypted_bytes = base64.b64decode(ciphertext)
    decrypted_padded = cipher.decrypt(encrypted_bytes)
    decrypted_text = unpad(decrypted_padded, Blowfish.block_size).decode()
    return decrypted_text

# Main function
if __name__ == "__main__":
    key = b"mysecretkey123"  # Key must be bytes and 4-56 bytes long
    print("Blowfish Encryption & Decryption")

    # User input for plaintext
    plaintext = input("Enter the plaintext to encrypt: ")
    print("\nOriginal plaintext:", plaintext)

    # Measure encryption time and memory usage
    tracemalloc.start()
    start_encrypt = time.time()
    encrypted_text = encrypt_blowfish(key, plaintext)
    end_encrypt = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("Encrypted (Base64):", encrypted_text)
    print(f"Encryption time: {end_encrypt - start_encrypt:.8f} seconds")
    print(f"Encryption memory usage: Current={current / 1024:.2f} KB, Peak={peak / 1024:.2f} KB")

    # Measure decryption time and memory usage
    tracemalloc.start()
    start_decrypt = time.time()
    decrypted_text = decrypt_blowfish(key, encrypted_text)
    end_decrypt = time.time()
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("Decrypted plaintext:", decrypted_text)
    print(f"Decryption time: {end_decrypt - start_decrypt:.8f} seconds")
    print(f"Decryption memory usage: Current={current / 1024:.2f} KB, Peak={peak / 1024:.2f} KB")
