"""Tests that verify code passes ruff lint and format checks."""

import subprocess

import pytest


@pytest.mark.code
class TestCode:
    """Test if code passes ruff lint + format."""

    def _check(self, args: list[str], error_message: str = None):
        """Run a check and raise AssertionError if it fails."""
        try:
            subprocess.run(args, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            output = exc.stdout + exc.stderr
            raise AssertionError(f"{error_message or str(exc)}\n{output}") from exc

    def test_ruff_format(self):
        """Test if code passes ruff format checks."""
        self._check(
            ["ruff", "format", "--check", "permyt/", "tests/"],
            error_message="Ruff format check failed. Some code should be reformatted.",
        )

    def test_ruff_lint(self):
        """Test if code passes ruff lint checks."""
        self._check(
            ["ruff", "check", "permyt/", "tests/"],
            error_message="Ruff lint failed. Some code contains errors.",
        )
