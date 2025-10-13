# Contributing to AWS Auto Block Attackers

Thank you for considering contributing to this project! We welcome contributions from the community.

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment for everyone.

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check existing issues. When creating a bug report, include:

- **Clear title and description**
- **Steps to reproduce**
- **Expected vs actual behavior**
- **Environment details** (Python version, AWS region, OS)
- **Log output** (with sensitive data redacted)

### Suggesting Enhancements

Enhancement suggestions are tracked as GitHub issues. When creating an enhancement suggestion, include:

- **Clear title and description**
- **Use case and rationale**
- **Proposed implementation** (if applicable)
- **Alternative approaches** you have considered

### Pull Requests

1. **Fork the repository** and create your branch from `main`
2. **Follow coding standards**: PEP 8, type hints where possible
3. **Add tests** for new functionality
4. **Update documentation** including docstrings and README if needed
5. **Ensure tests pass**: Run `pytest tests/`
6. **Run linting**: `black .` and `pylint auto_block_attackers.py`
7. **Write clear commit messages**: Follow conventional commits format

#### Pull Request Process

1. Update the README.md with details of changes if applicable
2. Update requirements.txt if adding dependencies
3. The PR will be merged once you have sign-off from a maintainer

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR-USERNAME/aws-auto-block-attackers.git
cd aws-auto-block-attackers

# Create virtual environment (or use uv)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Or use uv for dependency management
uv sync

# Install dependencies (development mode)
pip install -r requirements.txt

# Run tests
pytest tests/ -v

# Run linting
black .
pylint auto_block_attackers.py slack_client.py
```

## Coding Standards

### Python Style Guide

- Follow **PEP 8** style guide
- Use **type hints** for function parameters and return values
- Maximum line length: **100 characters** (flexibility for readability)
- Use **docstrings** for all public functions/classes (Google style)
- Use **meaningful variable names**

### Example Function

```python
def calculate_block_duration(hit_count: int, tier_config: List[Tuple]) -> timedelta:
    """
    Calculate block duration based on hit count and tier configuration.

    Args:
        hit_count: Number of malicious requests from the IP
        tier_config: List of tuples containing tier thresholds and durations

    Returns:
        timedelta object representing the block duration

    Raises:
        ValueError: If hit_count is negative or tier_config is invalid
    """
    if hit_count < 0:
        raise ValueError("Hit count cannot be negative")
    # Implementation...
```

## Testing Guidelines

### Writing Tests

- Use **pytest** for testing
- Aim for **>80% code coverage**
- Test both success and failure paths
- Use **mocking** for AWS API calls (use `moto` library)
- Include integration tests for critical workflows

### Running Tests

```bash
# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=. --cov-report=html

# Run specific test file
pytest tests/test_tier_system.py -v
```

## Documentation

- Keep README.md up to date
- Use clear, concise language
- Include code examples where helpful
- Document all configuration options
- Update CHANGELOG.md for significant changes

## Security

- **Never commit** AWS credentials, API tokens, or sensitive data
- Use environment variables or secure parameter stores
- Follow **principle of least privilege** for IAM permissions
- Report security vulnerabilities privately (see SECURITY.md)

## Version Control

### Branch Naming

- `feature/description` - New features
- `fix/description` - Bug fixes
- `docs/description` - Documentation updates
- `refactor/description` - Code refactoring
- `test/description` - Test additions/modifications

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types**: feat, fix, docs, style, refactor, test, chore

**Examples**:
- `feat(blocking): add support for IPv6 CIDR blocks`
- `fix(registry): handle corrupted JSON files gracefully`
- `docs(readme): update installation instructions`

## Release Process

1. Update version in `pyproject.toml`
2. Update CHANGELOG.md
3. Create pull request to `main`
4. After merge, create GitHub release with tag
5. Automated CI/CD publishes to PyPI (if configured)

## Questions?

Feel free to open an issue with the `question` label or start a discussion in GitHub Discussions.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing!**
