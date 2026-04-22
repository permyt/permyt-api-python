# Contributing to Permyt

Thank you for your interest in contributing to the PERMYT Python SDK!

## Development Setup

1. Clone the repository and create a virtual environment:

```bash
git clone https://github.com/LeopardLabsAi/permyt-api-python.git
cd permyt-api-python
python -m venv env
source env/bin/activate
```

2. Install with dev dependencies:

```bash
pip install -e ".[dev]"
```

## Code Style

- **Line length**: 100 characters (enforced by Black and Pylint).
- **Formatter**: [Black](https://github.com/psf/black) — run before committing.
- **Linter**: [Pylint](https://pylint.readthedocs.io/) — must pass with no errors.
- **Type checker**: [mypy](https://mypy-lang.org/) — must pass.

```bash
black permyt/
pylint permyt/
mypy permyt/
```

## Running Tests

```bash
pytest
```

Tests run with coverage reporting enabled. Check the terminal output or open
`htmlcov/index.html` for the coverage report.

## Submitting Changes

1. Fork the repo and create a feature branch from `main`.
2. Make your changes — keep commits focused and well-described.
3. Ensure all checks pass: `pytest`, `black --check`, `pylint`, `mypy`.
4. Open a pull request against `main` with a clear description of the change.

## Reporting Issues

Use [GitHub Issues](https://github.com/LeopardLabsAi/permyt-api-python/issues) to report
bugs or request features. Include steps to reproduce, expected vs actual behavior, and
your Python version.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
