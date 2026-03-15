from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


def generate_rsa_key_pair():
    return RSA.generate(2048)


def encrypt_rsa(public_key, message: str) -> bytes:
    # OAEP avoids padding oracle issues better than PKCS1 v1.5
    cipher = PKCS1_OAEP.new(public_key)
    return cipher.encrypt(message.encode())


def decrypt_rsa(private_key, ciphertext: bytes) -> str:
    cipher = PKCS1_OAEP.new(private_key)
    return cipher.decrypt(ciphertext).decode()


if __name__ == "__main__":
    message = "cle-session-abc123"
    key_pair = generate_rsa_key_pair()
    ciphertext = encrypt_rsa(key_pair.publickey(), message)
    decrypted_message = decrypt_rsa(key_pair, ciphertext)

    print("Original message:", message)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted message:", decrypted_message)

    wrong_key_pair = generate_rsa_key_pair()
    try:
        print("Wrong key test:", decrypt_rsa(wrong_key_pair, ciphertext))
    except Exception as error:
        print("Wrong private key detected:", error)
