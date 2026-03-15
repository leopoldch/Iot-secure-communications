from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from typing import Callable

from .errors import AuthenticationError, InvalidResponseError, ReplayAttackError
from .models import AuthenticationResponse, Challenge


def generate_shared_key(size: int = 32) -> bytes:
    """Return a random shared key."""

    if size <= 0:
        raise ValueError("size must be positive")
    return secrets.token_bytes(size)


class IoTDeviceAuthenticator:
    def __init__(
        self,
        device_id: str,
        shared_key: bytes,
        replay_window_seconds: int = 30,
        time_provider: Callable[[], int] | None = None,
    ) -> None:
        if not device_id:
            raise ValueError("device_id must not be empty")
        if not shared_key:
            raise ValueError("shared_key must not be empty")
        if replay_window_seconds <= 0:
            raise ValueError("replay_window_seconds must be positive")

        self.device_id = device_id
        self.shared_key = shared_key
        self.replay_window_seconds = replay_window_seconds
        self.time_provider = time_provider or (lambda: int(time.time()))
        self._seen_challenges: set[tuple[str, str]] = set()
        self._pending_challenges: dict[str, Challenge] = {}

    def create_challenge(self, receiver_id: str) -> Challenge:
        challenge = Challenge(
            sender_id=self.device_id,
            receiver_id=receiver_id,
            nonce=secrets.token_hex(16),
            timestamp=self.time_provider(),
        )
        self._pending_challenges[challenge.nonce] = challenge
        return challenge

    def answer_challenge(self, challenge: Challenge) -> AuthenticationResponse:
        self._validate_challenge(challenge)
        self._seen_challenges.add((challenge.sender_id, challenge.nonce))

        return AuthenticationResponse(
            sender_id=self.device_id,
            receiver_id=challenge.sender_id,
            nonce=challenge.nonce,
            timestamp=challenge.timestamp,
            hmac_value=self._compute_hmac(challenge, responder_id=self.device_id),
        )

    def verify_response(
        self,
        challenge: Challenge,
        response: AuthenticationResponse,
    ) -> bool:
        stored_challenge = self._pending_challenges.get(challenge.nonce)
        if stored_challenge != challenge:
            raise InvalidResponseError("unknown or already used challenge")

        if response.sender_id != challenge.receiver_id:
            raise InvalidResponseError("response sent by the wrong device")

        if response.receiver_id != self.device_id:
            raise InvalidResponseError("response receiver is invalid")

        if (
            response.nonce != challenge.nonce
            or response.timestamp != challenge.timestamp
        ):
            raise InvalidResponseError("response does not match the original challenge")

        expected_hmac = self._compute_hmac(challenge, responder_id=response.sender_id)
        if not hmac.compare_digest(response.hmac_value, expected_hmac):
            raise InvalidResponseError("invalid HMAC: wrong key or modified message")

        del self._pending_challenges[challenge.nonce]
        return True

    def mutual_authenticate(self, other_device: "IoTDeviceAuthenticator") -> bool:
        first_challenge = self.create_challenge(other_device.device_id)
        first_response = other_device.answer_challenge(first_challenge)
        self.verify_response(first_challenge, first_response)

        second_challenge = other_device.create_challenge(self.device_id)
        second_response = self.answer_challenge(second_challenge)
        other_device.verify_response(second_challenge, second_response)
        return True

    def _validate_challenge(self, challenge: Challenge) -> None:
        if challenge.receiver_id != self.device_id:
            raise AuthenticationError("challenge sent to the wrong device")

        if abs(self.time_provider() - challenge.timestamp) > self.replay_window_seconds:
            raise ReplayAttackError("challenge timestamp is outside the allowed window")

        challenge_key = (challenge.sender_id, challenge.nonce)
        if challenge_key in self._seen_challenges:
            raise ReplayAttackError("challenge nonce has already been used")

    def _compute_hmac(self, challenge: Challenge, responder_id: str) -> str:
        payload = (
            f"{challenge.sender_id}|{challenge.receiver_id}|"
            f"{challenge.nonce}|{challenge.timestamp}|{responder_id}"
        ).encode("utf-8")
        return hmac.new(self.shared_key, payload, hashlib.sha256).hexdigest()
