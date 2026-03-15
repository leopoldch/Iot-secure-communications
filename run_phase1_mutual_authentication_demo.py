#!/usr/bin/env python3

from __future__ import annotations

from iot_cloud_security.authentication import (
    AuthenticationError,
    InvalidResponseError,
    IoTDeviceAuthenticator,
    ReplayAttackError,
    generate_shared_key,
)


def run_success_scenario() -> None:
    shared_key = generate_shared_key()
    sensor = IoTDeviceAuthenticator("capteur-iot", shared_key)
    gateway = IoTDeviceAuthenticator("passerelle-locale", shared_key)

    sensor.mutual_authenticate(gateway)

    print(f"Clé partagée générée : {shared_key.hex()}")
    print("Authentification mutuelle réussie entre capteur-iot et passerelle-locale.")


def run_wrong_key_scenario() -> None:
    sensor = IoTDeviceAuthenticator("capteur-iot", generate_shared_key())
    gateway_with_wrong_key = IoTDeviceAuthenticator(
        "passerelle-locale",
        generate_shared_key(),
    )

    challenge = sensor.create_challenge("passerelle-locale")
    response = gateway_with_wrong_key.answer_challenge(challenge)

    try:
        sensor.verify_response(challenge, response)
    except InvalidResponseError as error:
        print(f"Échec attendu : {error}")


def run_replay_scenario() -> None:
    shared_key = generate_shared_key()
    sensor = IoTDeviceAuthenticator("capteur-iot", shared_key)
    gateway = IoTDeviceAuthenticator("passerelle-locale", shared_key)

    challenge = sensor.create_challenge("passerelle-locale")
    gateway.answer_challenge(challenge)

    try:
        gateway.answer_challenge(challenge)
    except ReplayAttackError as error:
        print(f"Rejeu détecté : {error}")


def run_expired_timestamp_scenario() -> None:
    current_time = [1000]

    def fake_time() -> int:
        return current_time[0]

    shared_key = generate_shared_key()
    sensor = IoTDeviceAuthenticator("capteur-iot", shared_key, time_provider=fake_time)
    gateway = IoTDeviceAuthenticator(
        "passerelle-locale",
        shared_key,
        time_provider=fake_time,
    )

    stale_challenge = sensor.create_challenge("passerelle-locale")
    current_time[0] += 60

    try:
        gateway.answer_challenge(stale_challenge)
    except ReplayAttackError as error:
        print(f"Horodatage refusé : {error}")


def main() -> None:
    run_success_scenario()
    run_wrong_key_scenario()
    run_replay_scenario()
    run_expired_timestamp_scenario()


if __name__ == "__main__":
    main()
