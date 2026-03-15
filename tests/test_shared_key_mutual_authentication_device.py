from __future__ import annotations

import unittest

from iot_cloud_security.authentication import (
    AuthenticationError,
    InvalidResponseError,
    IoTDeviceAuthenticator,
    ReplayAttackError,
)


class FakeTime:
    def __init__(self, start: int = 1_700_000_000) -> None:
        self.current = start

    def now(self) -> int:
        return self.current

    def advance(self, seconds: int) -> None:
        self.current += seconds


class IoTDeviceAuthenticatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.time = FakeTime()
        shared_key = b"0123456789ABCDEF0123456789ABCDEF"
        self.sensor = IoTDeviceAuthenticator(
            "sensor-alpha",
            shared_key,
            time_provider=self.time.now,
        )
        self.gateway = IoTDeviceAuthenticator(
            "gateway-beta",
            shared_key,
            time_provider=self.time.now,
        )

    def test_valid_response_is_accepted(self) -> None:
        challenge = self.sensor.create_challenge("gateway-beta")
        response = self.gateway.answer_challenge(challenge)

        self.assertTrue(self.sensor.verify_response(challenge, response))

    def test_wrong_shared_key_is_rejected(self) -> None:
        wrong_gateway = IoTDeviceAuthenticator(
            "gateway-beta",
            b"FEDCBA9876543210FEDCBA9876543210",
            time_provider=self.time.now,
        )
        challenge = self.sensor.create_challenge("gateway-beta")
        response = wrong_gateway.answer_challenge(challenge)

        with self.assertRaises(InvalidResponseError):
            self.sensor.verify_response(challenge, response)

    def test_reusing_the_same_challenge_nonce_is_detected(self) -> None:
        challenge = self.sensor.create_challenge("gateway-beta")
        self.gateway.answer_challenge(challenge)

        with self.assertRaises(ReplayAttackError):
            self.gateway.answer_challenge(challenge)

    def test_old_timestamp_is_rejected(self) -> None:
        challenge = self.sensor.create_challenge("gateway-beta")
        self.time.advance(31)

        with self.assertRaises(ReplayAttackError):
            self.gateway.answer_challenge(challenge)

    def test_challenge_sent_to_the_wrong_device_is_rejected(self) -> None:
        challenge = self.sensor.create_challenge("another-device")

        with self.assertRaises(AuthenticationError):
            self.gateway.answer_challenge(challenge)

    def test_response_cannot_be_verified_twice(self) -> None:
        challenge = self.sensor.create_challenge("gateway-beta")
        response = self.gateway.answer_challenge(challenge)

        self.sensor.verify_response(challenge, response)

        with self.assertRaises(InvalidResponseError):
            self.sensor.verify_response(challenge, response)


if __name__ == "__main__":
    unittest.main()
