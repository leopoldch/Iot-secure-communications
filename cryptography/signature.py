from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15


def sign(private_key, message: str) -> bytes:
    digest = SHA256.new(message.encode())
    return pkcs1_15.new(private_key).sign(digest)


def verify(public_key, message: str, signature: bytes) -> bool:
    digest = SHA256.new(message.encode())
    try:
        pkcs1_15.new(public_key).verify(digest, signature)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    message = "UNLOCK_DOOR: device=thermo-07, ts=1700000000"
    altered_message = message.replace("UNLOCK_DOOR", "LOCK_DOOR")
    key_pair = RSA.generate(2048)
    signed_message = sign(key_pair, message)

    print("Valid case:")
    print("Signature hex:", signed_message.hex())
    print("Verification:", verify(key_pair.publickey(), message, signed_message))

    print("\nAltered case:")
    print(
        "Verification:", verify(key_pair.publickey(), altered_message, signed_message)
    )
