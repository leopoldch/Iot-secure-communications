import os

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def encrypt(key, message: str):
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = pad(message.encode(), AES.block_size, style="pkcs7")
    return iv, cipher.encrypt(data)


def decrypt(key, iv: bytes, ciphertext: bytes) -> str:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    data = cipher.decrypt(ciphertext)
    return unpad(data, AES.block_size, style="pkcs7").decode()


if __name__ == "__main__":
    sensor_data = "Temperature: 22C, Humidity: 45%, Soil Moisture: 30%"
    key = os.urandom(16)
    iv, ciphertext = encrypt(key, sensor_data)

    print("Original message:", sensor_data)
    print("Ciphertext (hex):", ciphertext.hex())
    print("Decrypted message:", decrypt(key, iv, ciphertext))

    wrong_key = os.urandom(16)
    try:
        print("Wrong key test:", decrypt(wrong_key, iv, ciphertext))
    except Exception as error:
        print("Wrong key detected:", error)
