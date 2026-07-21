"""Ensures the repo root is importable so tests can `import evals.*`.

The `agentforge` package is importable via `pip install -e .`, but the top-level
`evals/` suite (case data + runner CLI) is intentionally not shipped in the
wheel. Placing this conftest at the repo root puts that root on sys.path for the
test session regardless of the working directory pytest is invoked from.
"""
