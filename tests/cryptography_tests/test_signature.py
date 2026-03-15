import unittest

from Crypto.PublicKey import RSA

import cryptography.signature as signature


class SignatureTests(unittest.TestCase):
    def test_valid_signature(self):
        message = "UNLOCK_DOOR: device=thermo-07, ts=1700000000"
        key_pair = RSA.generate(2048)
        signed = signature.sign(key_pair, message)
        self.assertTrue(signature.verify(key_pair.publickey(), message, signed))

    def test_altered_message(self):
        message = "UNLOCK_DOOR: device=thermo-07, ts=1700000000"
        altered_message = message.replace("UNLOCK_DOOR", "LOCK_DOOR")
        key_pair = RSA.generate(2048)
        signed = signature.sign(key_pair, message)
        self.assertFalse(
            signature.verify(key_pair.publickey(), altered_message, signed)
        )


if __name__ == "__main__":
    unittest.main()
