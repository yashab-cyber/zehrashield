# Contributing to ZehraShield

Thank you for your interest in contributing to ZehraShield! This document provides guidelines for contributing to the project.

## Code of Conduct

By participating in this project, you agree to abide by our code of conduct:

- Be respectful and inclusive
- Provide constructive feedback
- Focus on what's best for the community
- Show empathy towards other community members

## How to Contribute

### Reporting Bugs

Before creating bug reports, please check the existing issues to avoid duplicates. When creating a bug report, include:

- A clear and descriptive title
- Steps to reproduce the behavior
- Expected vs. actual behavior
- Screenshots (if applicable)
- Environment details (OS, Python version, etc.)

### Suggesting Enhancements

Enhancement suggestions are welcome! Please provide:

- A clear and descriptive title
- Detailed description of the proposed enhancement
- Explanation of why this enhancement would be useful
- Possible implementation approaches

### Pull Requests

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Add or update tests as needed
5. Update documentation
6. Ensure all tests pass
7. Submit a pull request

#### Pull Request Guidelines

- Follow the existing code style
- Include tests for new functionality
- Update documentation as needed
- Keep commits atomic and well-described
- Reference related issues in PR description

## Development Setup

### Prerequisites

- Python 3.8+
- Git
- Virtual environment tool (venv, conda, etc.)

### Local Development

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/zehrashield.git
cd zehrashield

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r requirements_advanced.txt

# Install development dependencies
pip install pytest pytest-cov flake8 black isort

# Run tests
python -m pytest tests/
```

### Code Style

We use Python PEP 8 style guidelines with some modifications:

- Line length: 100 characters
- Use black for code formatting
- Use isort for import sorting
- Use flake8 for linting

```bash
# Format code
black src/ tests/
isort src/ tests/

# Check style
flake8 src/ tests/
```

## Testing

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=src/

# Run specific test file
python -m pytest tests/test_firewall_engine.py

# Run integration tests
python test_integration.py
```

### Writing Tests

- Write tests for all new functionality
- Use descriptive test names
- Test both success and failure cases
- Mock external dependencies
- Aim for >90% code coverage

## Documentation

### Code Documentation

- Use docstrings for all public functions and classes
- Follow Google or NumPy docstring format
- Include parameter types and return values
- Provide usage examples for complex functions

### User Documentation

- Update relevant documentation files
- Include examples and use cases
- Keep documentation up-to-date with code changes
- Test all examples and commands

## Commit Messages

Use clear and meaningful commit messages:

```
type(scope): brief description

Longer explanation if necessary

Fixes #issue_number
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

## Branch Naming

Use descriptive branch names:

- `feature/add-new-layer`
- `bugfix/fix-memory-leak`
- `docs/update-api-reference`
- `refactor/improve-performance`

## Security

### Reporting Security Vulnerabilities

Please do not report security vulnerabilities through public GitHub issues. Instead:

1. Email: security@zehrasec.com
2. Include detailed description
3. Provide steps to reproduce
4. Allow time for investigation before public disclosure

### Security Guidelines

- Never commit secrets or credentials
- Use environment variables for configuration
- Follow secure coding practices
- Validate all inputs
- Use proper authentication and authorization

## License

By contributing to ZehraShield, you agree that your contributions will be licensed under the same license as the project.

## Recognition

Contributors will be recognized in:

- CONTRIBUTORS.md file
- Release notes
- Project documentation

## Getting Help

If you need help with contributing:

- Join our community discussions
- Check existing documentation
- Ask questions in issues (use "question" label)
- Contact maintainers directly

## Release Process

### Version Numbering

We follow Semantic Versioning (SemVer):

- MAJOR.MINOR.PATCH
- MAJOR: Breaking changes
- MINOR: New features (backward compatible)
- PATCH: Bug fixes (backward compatible)

### Release Checklist

1. Update version numbers
2. Update CHANGELOG.md
3. Run full test suite
4. Update documentation
5. Create release notes
6. Tag release
7. Deploy to appropriate channels

## Community

### Communication Channels

- GitHub Issues: Bug reports and feature requests
- GitHub Discussions: General questions and discussions
- Email: security@zehrasec.com (security issues)
- Email: support@zehrasec.com (general support)

### Maintainers

Current maintainers:

- Yashab Alam (@yashab-cyber) - Project Lead

## Thank You

Thank you for contributing to ZehraShield! Your contributions help make enterprise security more accessible and effective.

---

For more information, visit our [website](https://zehrasec.com) or check our [documentation](docs/).
