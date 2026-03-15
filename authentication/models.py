from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Challenge:
    """Message sent by a device to prove the peer knows the shared key."""

    sender_id: str
    receiver_id: str
    nonce: str
    timestamp: int


@dataclass(frozen=True)
class AuthenticationResponse:
    """Answer to a challenge, protected by HMAC-SHA256."""

    sender_id: str
    receiver_id: str
    nonce: str
    timestamp: int
    hmac_value: str
