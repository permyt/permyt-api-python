"""Tests that verify code passes black and pylint checks."""

import subprocess

import pytest


@pytest.mark.code
class TestCode:
    """Test if code passes black and pylint."""

    def _check(self, args: list[str], error_message: str = None):
        """Run a check and raise AssertionError if it fails."""
        try:
            subprocess.run(args, check=True, capture_output=True, text=True)
        except subprocess.CalledProcessError as exc:
            output = exc.stdout + exc.stderr
            raise AssertionError(f"{error_message or str(exc)}\n{output}") from exc

    def test_black(self):
        """Test if code passes black checks."""
        self._check(
            ["black", "--check", "permyt/"],
            error_message="Black checks failed. Some code should be reformatted.",
        )

    def test_pylint(self):
        """Test if code passes pylint checks."""
        self._check(
            ["pylint", "permyt/"],
            error_message="Pylint checks failed. Some code contains errors.",
        )
