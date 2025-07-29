# Contributing to SubSpyder

Thank you for your interest in contributing to SubSpyder! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Types of Contributions

We welcome various types of contributions:

- **🐛 Bug Reports**: Report bugs and issues
- **✨ Feature Requests**: Suggest new features
- **📝 Documentation**: Improve documentation
- **🔧 Code Improvements**: Fix bugs, add features, improve performance
- **🧪 Testing**: Add tests or improve test coverage
- **🌐 Translations**: Help with internationalization

### Before You Start

1. **Check existing issues**: Search for similar issues before creating new ones
2. **Read the documentation**: Familiarize yourself with the project structure
3. **Set up development environment**: Follow the setup guide in [SETUP_GUIDE.md](SETUP_GUIDE.md)

## 🚀 Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- pip

### Local Development

```bash
# 1. Fork and clone the repository
git clone https://github.com/YOUR_USERNAME/subspyder.git
cd subspyder

# 2. Create a virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# 3. Install in development mode
pip install -e .

# 4. Install development dependencies
pip install -r requirements.txt

# 5. Set up configuration
cp subspyder_config_template.ini subspyder_config.ini
# Edit subspyder_config.ini with your API keys
```

## 📝 Code Style Guidelines

### Python Code Style

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guidelines
- Use meaningful variable and function names
- Add docstrings to all public functions and classes
- Keep functions focused and single-purpose
- Use type hints where appropriate

### Example Code Style

```python
def enumerate_subdomains(domain: str, config: Config) -> List[str]:
    """
    Enumerate subdomains for a given domain.
    
    Args:
        domain: The target domain to enumerate
        config: Configuration object with API keys
        
    Returns:
        List of discovered subdomains
        
    Raises:
        ValueError: If domain is invalid
    """
    if not domain or '.' not in domain:
        raise ValueError("Invalid domain provided")
    
    # Implementation here
    return subdomains
```

### File Organization

- Keep related functionality in the same module
- Use descriptive file names
- Follow the existing package structure
- Add `__init__.py` files to new packages

## 🔧 Making Changes

### 1. Create a Feature Branch

```bash
# Create and switch to a new branch
git checkout -b feature/your-feature-name

# Or for bug fixes
git checkout -b fix/your-bug-description
```

### 2. Make Your Changes

- Write clear, focused commits
- Test your changes thoroughly
- Update documentation if needed
- Add tests for new functionality

### 3. Commit Guidelines

Use conventional commit messages:

```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(api): add new VirusTotal integration
fix(validator): resolve timeout issues with large domains
docs(readme): update installation instructions
```

### 4. Testing Your Changes

```bash
# Run basic tests
python subspyder_cli.py --help

# Test with a sample domain
python subspyder_cli.py example.com

# Test individual modules
python example_usage.py
```

### 5. Submit a Pull Request

1. **Push your branch**:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what was changed
   - Reference to any related issues
   - Screenshots if UI changes were made

## 🧪 Testing Guidelines

### Writing Tests

- Add tests for new functionality
- Ensure existing tests still pass
- Test edge cases and error conditions
- Use descriptive test names

### Running Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python -m pytest tests/test_passive.py

# Run with coverage
python -m pytest --cov=subspyder
```

## 📚 Documentation

### Updating Documentation

- Update README.md for user-facing changes
- Update docstrings for code changes
- Update SETUP_GUIDE.md for setup changes
- Add inline comments for complex logic

### Documentation Standards

- Use clear, concise language
- Include code examples
- Keep documentation up-to-date
- Use proper markdown formatting

## 🐛 Bug Reports

### Creating Bug Reports

When reporting bugs, please include:

1. **Clear description** of the problem
2. **Steps to reproduce** the issue
3. **Expected behavior** vs actual behavior
4. **Environment details**:
   - Operating system
   - Python version
   - SubSpyder version
5. **Error messages** and logs
6. **Configuration** (without API keys)

### Bug Report Template

```markdown
## Bug Description
Brief description of the issue

## Steps to Reproduce
1. Step 1
2. Step 2
3. Step 3

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Windows 10, macOS 12, Ubuntu 20.04]
- Python: [e.g., 3.9.7]
- SubSpyder: [e.g., 1.0.0]

## Error Messages
```
Paste error messages here
```

## Additional Information
Any other relevant information
```

## ✨ Feature Requests

### Creating Feature Requests

When requesting features, please include:

1. **Clear description** of the feature
2. **Use case** and motivation
3. **Proposed implementation** (if you have ideas)
4. **Alternative solutions** considered
5. **Impact** on existing functionality

## 🔒 Security

### Security Issues

If you discover a security vulnerability:

1. **Do not** create a public issue
2. **Email** the maintainers directly
3. **Provide** detailed information about the vulnerability
4. **Wait** for acknowledgment before public disclosure

## 📋 Pull Request Checklist

Before submitting a PR, ensure:

- [ ] Code follows style guidelines
- [ ] Tests pass
- [ ] Documentation is updated
- [ ] No sensitive data is included
- [ ] Commit messages are clear
- [ ] Branch is up-to-date with main
- [ ] Changes are focused and minimal

## 🎯 Review Process

### What We Look For

- **Code quality**: Clean, readable, maintainable code
- **Functionality**: Works as intended
- **Testing**: Adequate test coverage
- **Documentation**: Clear and complete
- **Security**: No security vulnerabilities
- **Performance**: No significant performance regressions

### Review Timeline

- Initial review: Within 1-2 days
- Follow-up reviews: Within 1 day of updates
- Merge: After approval and CI checks pass

## 🏆 Recognition

Contributors will be recognized in:

- Project README
- Release notes
- GitHub contributors list
- Documentation

## 📞 Getting Help

If you need help contributing:

- **Documentation**: Check [SETUP_GUIDE.md](SETUP_GUIDE.md)
- **Issues**: Search existing issues
- **Discussions**: Use GitHub Discussions
- **Code**: Review existing code for examples

## 🎉 Thank You!

Thank you for contributing to SubSpyder! Your contributions help make this tool better for everyone in the security community. 