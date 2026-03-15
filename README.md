# IoT-Cloud Security

## Installation with uv

1. Install `uv` if needed.
2. From the project root, run:

```bash
uv sync
```

## Run the tests

```bash
uv run python -m unittest discover -s tests -v
```

## Run the demonstration

```bash
uv run python run_phase1_mutual_authentication_demo.py
```

## Run the cryptography scripts

```bash
uv run python cryptography/aes.py
uv run python cryptography/rsa.py
uv run python cryptography/signature.py
```
