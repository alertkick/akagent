# Contributing to AlertKick Agent

Thank you for your interest in contributing to the AlertKick Agent! This document provides guidelines and information for contributors.

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to providing a welcoming and inclusive environment for all contributors.

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request, please open an issue on GitHub. When reporting bugs, please include:

- Your operating system and version
- Go version
- Agent version
- Steps to reproduce the issue
- Expected vs actual behavior
- Any relevant log output

### Submitting Changes

1. Fork the repository
2. Create a feature branch from `main`
3. Make your changes
4. Ensure tests pass: `make test`
5. Run the linter: `make audit`
6. Submit a pull request

### Coding Standards

- Follow standard Go formatting (`go fmt`)
- Write clear, descriptive commit messages
- Include tests for new functionality
- Update documentation as needed
- Keep pull requests focused on a single change

### Commit Message Format

Use clear, descriptive commit messages:

```
Short summary (50 chars or less)

More detailed description if needed. Wrap at 72 characters.
Explain what and why, not how.

Fixes #123
```

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/apagent.git
cd apagent

# Build the agent
make build

# Run tests
make test

# Run linters
make audit
```

## Testing

Please ensure all tests pass before submitting a pull request:

```bash
make test
```

## Questions?

If you have questions, feel free to open an issue for discussion.

