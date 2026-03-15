from __future__ import annotations

import unittest

from iot_cloud_security.authentication import IoTDeviceAuthenticator


class FakeTime:
    def __init__(self, start: int = 1_700_000_000) -> None:
        self.current = start

    def now(self) -> int:
        return self.current


class MutualAuthenticationFlowTests(unittest.TestCase):
    def test_mutual_authentication_succeeds_in_both_directions(self) -> None:
        shared_key = b"0123456789ABCDEF0123456789ABCDEF"
        fake_time = FakeTime()

        sensor = IoTDeviceAuthenticator(
            "sensor-alpha",
            shared_key,
            time_provider=fake_time.now,
        )
        gateway = IoTDeviceAuthenticator(
            "gateway-beta",
            shared_key,
            time_provider=fake_time.now,
        )

        self.assertTrue(sensor.mutual_authenticate(gateway))


if __name__ == "__main__":
    unittest.main()
