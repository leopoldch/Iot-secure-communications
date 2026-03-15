import unittest

import cryptography.aes as aes


class AESTests(unittest.TestCase):
    def test_encrypt_and_decrypt(self):
        message = "Temperature: 22C, Humidity: 45%, Soil Moisture: 30%"
        key = b"0123456789abcdef"
        iv, ciphertext = aes.encrypt(key, message)
        self.assertEqual(aes.decrypt(key, iv, ciphertext), message)

    def test_wrong_key(self):
        message = "Temperature: 22C, Humidity: 45%, Soil Moisture: 30%"
        good_key = b"0123456789abcdef"
        wrong_key = b"abcdef0123456789"
        iv, ciphertext = aes.encrypt(good_key, message)
        try:
            result = aes.decrypt(wrong_key, iv, ciphertext)
        except Exception:
            return
        self.assertNotEqual(result, message)


if __name__ == "__main__":
    unittest.main()
