# Contributing to CRT Hosts Enricher

Thank you for your interest in contributing to CRT Hosts Enricher! This document provides guidelines and information for contributors.

## 🤝 How to Contribute

### Reporting Issues

1. **Check existing issues** first to avoid duplicates
2. **Use the issue templates** when available
3. **Provide detailed information**:
   - Operating system and Python version
   - Complete error messages and stack traces
   - Steps to reproduce the issue
   - Expected vs actual behavior

### Suggesting Features

1. **Open an issue** with the "enhancement" label
2. **Describe the use case** and why it would be valuable
3. **Provide examples** of how it would work
4. **Consider backwards compatibility**

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/amazing-feature`
3. **Make your changes**
4. **Test thoroughly**
5. **Commit with clear messages**
6. **Push and create a Pull Request**

## 🛠 Development Setup

### Prerequisites

- Python 3.6 or higher
- Git
- Text editor or IDE

### Setup Steps

```bash
# Clone your fork
git clone https://github.com/gioguanuo/crt_hosts_enricher.git
cd crt_hosts_enricher

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements.txt

# Install pre-commit hooks (optional but recommended)
pip install pre-commit
pre-commit install
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=crt_hosts_enricher

# Run specific test file
python -m pytest tests/test_specific.py

# Run with verbose output
python -m pytest -v
```

### Code Quality

```bash
# Format code with black
black crt_hosts_enricher.py

# Check style with flake8
flake8 crt_hosts_enricher.py

# Type checking with mypy
mypy crt_hosts_enricher.py
```

## 📝 Code Style Guidelines

### Python Style

- Follow **PEP 8** style guidelines
- Use **black** for code formatting
- Maximum line length: **88 characters**
- Use **type hints** where appropriate
- Write **docstrings** for all functions and classes

### Example Function

```python
def fetch_hostnames(domain: str, timeout: float = 60.0) -> List[str]:
    """
    Fetch hostnames from crt.sh for the given domain.
    
    Args:
        domain: Target domain to search
        timeout: HTTP timeout in seconds
        
    Returns:
        List of unique hostnames found
        
    Raises:
        HTTPError: If crt.sh request fails
        ValueError: If domain is invalid
    """
    # Implementation here
    pass
```

### Logging Guidelines

- Use appropriate log levels:
  - `DEBUG`: Detailed diagnostic information
  - `INFO`: General information about program execution
  - `WARNING`: Something unexpected happened
  - `ERROR`: Serious problem occurred
  - `CRITICAL`: Very serious error occurred

```python
import logging

logger = logging.getLogger(__name__)

def example_function():
    logger.debug("Starting hostname resolution")
    logger.info("Processing 150 hostnames")
    logger.warning("API rate limit approaching")
    logger.error("Failed to resolve hostname: example.com")
```

### Error Handling

- Use specific exception types
- Provide helpful error messages
- Log errors appropriately
- Don't suppress exceptions without good reason

```python
try:
    result = api_call()
except requests.HTTPError as e:
    logger.error(f"HTTP error during API call: {e}")
    raise
except requests.Timeout:
    logger.warning("API call timed out, retrying...")
    # Retry logic here
```

## 🧪 Testing Guidelines

### Test Structure

```
tests/
├── __init__.py
├── test_core.py           # Core functionality tests
├── test_api.py            # API integration tests
├── test_utils.py          # Utility function tests
├── test_cli.py            # Command-line interface tests
└── fixtures/              # Test data files
    ├── sample_crt_response.json
    └── sample_ipinfo_response.json
```

### Writing Tests

```python
import pytest
from unittest.mock import patch, Mock

def test_hostname_extraction():
    """Test hostname extraction from crt.sh data"""
    # Arrange
    sample_data = [
        {"common_name": "example.com", "name_value": "example.com\nwww.example.com"},
        {"common_name": "api.example.com", "name_value": "api.example.com"}
    ]
    
    # Act
    hostnames = extract_hostnames(sample_data)
    
    # Assert
    expected = ["api.example.com", "example.com", "www.example.com"]
    assert sorted(hostnames) == expected

@patch('urllib.request.urlopen')
def test_api_call_with_retry(mock_urlopen):
    """Test API call with retry mechanism"""
    # Mock setup
    mock_response = Mock()
    mock_response.read.return_value = b'{"result": "success"}'
    mock_urlopen.return_value.__enter__.return_value = mock_response
    
    # Test the function
    result = api_call_with_retry("https://api.example.com")
    
    # Assertions
    assert result == {"result": "success"}
    mock_urlopen.assert_called_once()
```

### Test Categories

1. **Unit Tests**: Test individual functions in isolation
2. **Integration Tests**: Test interaction between components
3. **API Tests**: Test external API integrations (with mocking)
4. **CLI Tests**: Test command-line interface

## 📋 Pull Request Guidelines

### Before Submitting

- [ ] Code follows style guidelines
- [ ] Tests pass locally
- [ ] New features have tests
- [ ] Documentation is updated
- [ ] Commit messages are clear
- [ ] Branch is up to date with main

### Pull Request Template

```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests added/updated
- [ ] All tests pass
- [ ] Manual testing completed

## Documentation
- [ ] README updated
- [ ] Docstrings added/updated
- [ ] Examples provided

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Breaking changes documented
```

### Commit Messages

Use clear, descriptive commit messages:

```bash
# Good
git commit -m "Add BGPView integration for CIDR lookup"
git commit -m "Fix timeout handling in HTTP retry logic"
git commit -m "Update README