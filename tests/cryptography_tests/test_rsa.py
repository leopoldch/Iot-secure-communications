import unittest

import cryptography.rsa as rsa


class RSATests(unittest.TestCase):
    def test_encrypt_and_decrypt(self):
        message = "cle-session-abc123"
        key_pair = rsa.generate_rsa_key_pair()
        ciphertext = rsa.encrypt_rsa(key_pair.publickey(), message)
        self.assertEqual(rsa.decrypt_rsa(key_pair, ciphertext), message)

    def test_wrong_private_key(self):
        message = "cle-session-abc123"
        good_key_pair = rsa.generate_rsa_key_pair()
        wrong_key_pair = rsa.generate_rsa_key_pair()
        ciphertext = rsa.encrypt_rsa(good_key_pair.publickey(), message)
        with self.assertRaises(ValueError):
            rsa.decrypt_rsa(wrong_key_pair, ciphertext)


if __name__ == "__main__":
    unittest.main()
