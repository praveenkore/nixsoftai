# VulnGuard Technology Stack

## Technologies Used

### Core Language

- **Python 3.8+** - Primary programming language
  - Type hints for all function signatures
  - PEP 8 compliance enforced
  - Object-oriented design patterns

### Core Dependencies

#### Python Libraries

1. **PyYAML >= 6.0**
   - Purpose: Configuration file parsing and generation
   - Usage: Loading benchmark rules and agent configuration
   - Key Features: Safe YAML loading, schema validation

2. **jsonschema >= 4.17.0**
   - Purpose: JSON schema validation for AI output and configuration
   - Usage: Validating AI advisory responses and configuration files
   - Key Features: Schema validation, detailed error messages

3. **click >= 8.1.0**
   - Purpose: CLI framework for command-line interface
   - Usage: Building CLI commands and argument parsing
   - Key Features: Argument parsing, help generation, command groups

4. **psutil >= 5.9.0**
   - Purpose: System information gathering
   - Usage: Collecting system information for logging
   - Key Features: Cross-platform system metrics, process information

5. **python-json-logger >= 2.0.0**
   - Purpose: Structured JSON logging
   - Usage: Audit logging in JSON-line format
   - Key Features: JSON formatting, log rotation support

6. **python-dotenv >= 1.0.0**
   - Purpose: Environment variable management
   - Usage: Loading API keys and configuration from .env files
   - Key Features: Secure environment variable loading, .env file support

#### LLM Integration Dependencies

7. **openai >= 1.0.0** (for OpenAI provider)
   - Purpose: OpenAI API client
   - Usage: GPT model integration for AI advisory
   - Key Features: Type-safe API client, async support, streaming

8. **anthropic >= 0.18.0** (for Anthropic provider)
   - Purpose: Anthropic API client
   - Usage: Claude model integration for AI advisory
   - Key Features: Type-safe API client, message-based API

9. **httpx >= 0.25.0** (for HTTP requests)
   - Purpose: Async HTTP client for LLM API calls
   - Usage: Making HTTP requests to LLM providers
   - Key Features: Connection pooling, async support, timeout handling

#### Testing Dependencies

10. **pytest >= 7.4.0**
    - Purpose: Testing framework
    - Usage: Unit and integration testing
    - Key Features: Fixtures, parametrization, coverage integration

11. **pytest-cov >= 4.1.0**
    - Purpose: Test coverage measurement
    - Usage: Tracking code coverage for test suite
    - Key Features: Coverage reporting, HTML reports

12. **pytest-mock >= 3.11.0**
    - Purpose: Mocking utilities for testing
    - Usage: Mocking external dependencies in tests
    - Key Features: Mock objects, patching, spy utilities

#### Code Quality Dependencies

13. **black >= 23.7.0**
    - Purpose: Code formatting
    - Usage: Enforcing consistent code style
    - Key Features: PEP 8 compliant, deterministic formatting

14. **flake8 >= 6.1.0**
    - Purpose: Code linting
    - Usage: Static code analysis and error detection
    - Key Features: PEP 8 checking, plugin support

15. **mypy >= 1.5.0**
    - Purpose: Static type checking
    - Usage: Type checking Python code
    - Key Features: Type inference, error detection, strict mode

16. **types-PyYAML >= 6.0.0**
    - Purpose: Type stubs for PyYAML
    - Usage: Type checking PyYAML usage
    - Key Features: Complete type annotations

17. **types-psutil >= 5.9.0**
    - Purpose: Type stubs for psutil
    - Usage: Type checking psutil usage
    - Key Features: Complete type annotations

18. **types-click >= 7.1.0**
    - Purpose: Type stubs for click
    - Usage: Type checking click usage
    - Key Features: Complete type annotations

#### Optional Local LLM Dependencies

The following dependencies are optional and only required for local LLM support:

19. **transformers >= 4.35.0**
    - Purpose: Local model loading and inference
    - Usage: Loading Hugging Face format models
    - Key Features: Model parallelism, quantization support

20. **torch >= 2.1.0**
    - Purpose: PyTorch tensor operations
    - Usage: Model inference and GPU acceleration
    - Key Features: CUDA support, automatic differentiation

21. **accelerate >= 0.25.0**
    - Purpose: Model acceleration library
    - Usage: Distributed training and inference
    - Key Features: Device mapping, mixed precision

22. **sentencepiece >= 0.1.99**
    - Purpose: Subword tokenization
    - Usage: Tokenizer for language models
    - Key Features: BPE and unigram language model support

**Note:** These dependencies are commented out in requirements.txt by default. Uncomment them if you need local LLM support. The codebase uses `TYPE_CHECKING` pattern to prevent Pylance import resolution errors while maintaining safe optional dependency handling.

## Development Setup

### Prerequisites

- Python 3.8 or higher
- Git
- Virtual environment (recommended)
- Linux development environment (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)

### Installation Steps

1. **Clone repository:**
```bash
git clone https://github.com/praveenkore/nixsoftai.git
cd nixsoftai
```

2. **Create virtual environment:**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies:**
```bash
pip install -r requirements.txt
```

4. **Install development dependencies:**
```bash
pip install pytest pytest-cov black flake8 mypy python-json-logger
```

5. **Verify installation:**
```bash
python -m vulnguard.main version
```

### Development Environment

#### Recommended IDE Setup

**VS Code Extensions:**
- Python (Microsoft)
- Pylance (Microsoft)
- Python Test Explorer (LittleFoxTeam)
- YAML (Red Hat)

**VS Code Settings:**
```json
{
  "python.linting.enabled": true,
  "python.linting.flake8Enabled": true,
  "python.linting.mypyEnabled": true,
  "python.formatting.provider": "black",
  "python.testing.pytestEnabled": true,
  "python.testing.pytestArgs": [
    "tests"
  ],
  "editor.formatOnSave": true,
  "editor.codeActionsOnSave": {
    "source.organizeImports": true
  }
}
```

**PyCharm Settings:**
- Code Style: Use Black formatter
- Inspections: Enable Flake8 and MyPy
- Testing: Configure pytest runner
- Interpreter: Use project virtual environment

## Technical Constraints

### Platform Constraints

- **Operating System**: Linux only (no Windows/macOS support)
- **Minimum Python Version**: 3.8
- **Supported Linux Distributions**:
  - Red Hat Enterprise Linux (RHEL) 8+
  - Ubuntu 20.04+
  - CentOS 8+
  - Debian 10+

### Security Constraints

- **Command Execution**: Never use `shell=True` for command execution
- **File Permissions**: All files must have secure permissions (0600 for files, 0700 for directories)
- **File Operations**: All file operations must be atomic to prevent TOCTOU vulnerabilities
- **AI Validation**: All AI output must be validated before use
- **Command Validation**: All commands must be validated against allow-list/block-list

### Performance Constraints

- **Scanning**: Deterministic checks with timeout protection
- **LLM Requests**: Rate limiting to prevent API quota exhaustion
- **Connection Pooling**: Efficient HTTP connection reuse
- **Memory Usage**: Lazy loading to avoid circular dependencies

### Legal Constraints

- **License**: GNU General Public License v3 (GPL-3.0)
- **Attribution**: Nixsoft Technologies Pvt. Ltd. must be credited
- **Project Name**: "VulnGuard" must not be rebranded
- **Derivative Works**: Must also be released under GPL v3

## Dependencies

### External Dependencies

#### System Dependencies

- **Python 3.8+** - Required runtime environment
- **Linux OS** - Required operating system (RHEL 8+, Ubuntu 20.04+, CentOS 8+, Debian 10+)
- **Root or sudo access** - Required for remediation operations
- **Network access** - Required for cloud LLM providers (optional)

#### Python Dependencies

See [`requirements.txt`](../requirements.txt) for complete list:

**Core Dependencies:**
- PyYAML >= 6.0
- jsonschema >= 4.17.0
- click >= 8.1.0
- psutil >= 5.9.0
- python-json-logger >= 2.0.0
- python-dotenv >= 1.0.0

**LLM Provider Dependencies:**
- openai >= 1.0.0 (for OpenAI provider)
- anthropic >= 0.18.0 (for Anthropic provider)
- httpx >= 0.25.0 (for HTTP requests)

**Testing Dependencies:**
- pytest >= 7.4.0
- pytest-cov >= 4.1.0
- pytest-mock >= 3.11.0

**Code Quality Dependencies:**
- black >= 23.7.0
- flake8 >= 6.1.0
- mypy >= 1.5.0

**Type Stub Dependencies:**
- types-PyYAML >= 6.0.0
- types-psutil >= 5.9.0
- types-click >= 7.1.0

## Tool Usage Patterns

### Code Formatting

**Black** - Code formatter
```bash
# Format all files
black vulnguard/

# Format specific file
black vulnguard/main.py

# Check formatting without making changes
black --check vulnguard/
```

### Code Linting

**Flake8** - Code linter
```bash
# Lint all files
flake8 vulnguard/

# Lint specific file
flake8 vulnguard/main.py

# Show more details
flake8 --max-line-length=100 vulnguard/
```

### Type Checking

**MyPy** - Static type checker
```bash
# Type check all files
mypy vulnguard/

# Type check specific file
mypy vulnguard/main.py

# Show more details
mypy --show-error-codes vulnguard/
```

### Testing

**pytest** - Testing framework
```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_scanner.py

# Run with coverage
pytest --cov=vulnguard --cov-report=html

# Run with verbose output
pytest -v
```

### Configuration Management

**YAML** - Configuration format
```bash
# Validate configuration
python -c "import yaml; yaml.safe_load(open('vulnguard/configs/agent/config.yaml'))"

# Edit configuration
nano vulnguard/configs/agent/config.yaml
```

**Environment Variables** - `.env` file
```bash
# Copy example file
cp .env.example .env

# Edit with your values
nano .env

# Load environment variables
source .env
```

## Development Workflow

### Branching Strategy

1. **Create feature branch:**
```bash
git checkout -b feature/your-feature-name
```

2. **Make changes:**
```bash
# Edit files
git add .
git commit -m "feat: add new feature"
```

3. **Run tests:**
```bash
pytest
```

4. **Run linting:**
```bash
black vulnguard/
flake8 vulnguard/
mypy vulnguard/
```

5. **Push changes:**
```bash
git push origin feature/your-feature-name
```

6. **Create pull request:**
```bash
# Create PR on GitHub/GitLab
```

### Code Review Process

1. **Automated Checks:**
   - All tests must pass
   - Code must pass linting (flake8)
   - Code must pass type checking (mypy)
   - Code must be formatted with black

2. **Manual Review:**
   - Review code for security vulnerabilities
   - Review code for performance issues
   - Review code for maintainability
   - Review documentation for completeness

3. **Approval:**
   - Code must be approved by maintainer
   - All review comments must be addressed
   - Changes must be squashed before merge

### Release Process

1. **Version Bump:**
   - Update version in `vulnguard/__init__.py`
   - Update version in `vulnguard/configs/agent/config.yaml`
   - Update CHANGELOG.md

2. **Tag Release:**
```bash
git tag -a v1.0.0 -m "Release version 1.0.0"
git push origin v1.0.0
```

3. **Build Distribution:**
```bash
python setup.py sdist bdist_wheel
```

4. **Upload to PyPI:**
```bash
twine upload dist/*
```

## Security Considerations

### API Key Security

- **Never commit** `.env` files with real API keys
- **Rotate keys** regularly (every 90 days)
- **Use environment variables** in production
- **Monitor usage** for unauthorized access

### Data Privacy

- **OpenAI/Anthropic**: Data is sent to external API
- **Local LLM**: Data stays on your system
- **Review privacy policies** of external providers

### Output Validation

All AI output is validated:
- JSON schema validation
- Command allow-list/block-list validation
- Confidence threshold checking
- Required field verification

## Performance Considerations

### Scanning Performance

- **Deterministic checks**: Fast, predictable execution
- **Timeout protection**: Prevents hanging operations
- **OS filtering**: Only runs compatible rules

### LLM Request Performance

- **Connection pooling**: Reuses HTTP connections
- **Rate limiting**: Prevents API quota exhaustion
- **Retry logic**: Exponential backoff for resilience
- **Timeout handling**: Prevents hanging requests

### Memory Management

- **Lazy loading**: Avoids circular dependencies
- **Efficient data structures**: Minimizes memory footprint
- **Log rotation**: Prevents disk space issues

## Best Practices

### Code Quality

1. **Type Hints**: Use type hints for all function signatures
2. **Docstrings**: Use Google-style docstrings for all functions
3. **Error Handling**: Log all errors and return appropriate values
4. **Validation**: Validate all inputs and outputs
5. **Testing**: Write comprehensive tests for all functionality

### Security

1. **Command Execution**: Never use `shell=True`
2. **File Permissions**: Always specify secure permissions
3. **File Operations**: Use atomic operations
4. **Input Validation**: Validate all user inputs
5. **Output Validation**: Validate all AI outputs

### Performance

1. **Connection Pooling**: Reuse HTTP connections
2. **Rate Limiting**: Prevent API quota exhaustion
3. **Lazy Loading**: Avoid circular dependencies
4. **Efficient Algorithms**: Use optimal algorithms for operations

### Documentation

1. **README**: Keep README.md up-to-date
2. **API Docs**: Document all public APIs
3. **Architecture Docs**: Document system architecture
4. **Configuration Docs**: Document all configuration options
5. **Development Docs**: Document development workflow

## Troubleshooting

### Common Issues

#### Issue: "API key not found"

**Solution:**
```bash
# Check if environment variable is set
echo $OPENAI_API_KEY

# Set environment variable
export OPENAI_API_KEY=sk-your-key-here

# Or add to .env file
echo "OPENAI_API_KEY=sk-your-key-here" >> .env
```

#### Issue: "Failed to initialize LLM client"

**Solution:**
- Check configuration file syntax
- Verify provider name is correct (openai, anthropic, local, mock)
- Check API key format
- Ensure dependencies are installed

#### Issue: "AI confidence below threshold"

**Solution:**
- Lower `min_confidence_threshold` in config
- Review AI output quality
- Consider using a different model

#### Issue: "Local LLM requires transformers and torch"

**Solution:**
```bash
# Install required dependencies
pip install transformers torch accelerate

# For GPU support
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
```

#### Issue: "CUDA out of memory"

**Solution:**
- Use a smaller model
- Reduce `max_tokens` in config
- Use CPU instead of GPU (`device: "cpu"`)

### Debug Mode

Enable debug logging for troubleshooting:

```yaml
logging:
  level: "DEBUG"
  format: "text"
```

### Testing LLM Connection

Test LLM connection independently:

```python
from vulnguard.pkg.advisor.llm_client import create_llm_client

# Create client
client = create_llm_client(
    provider="openai",
    config={"api_key": "your-key", "model": "gpt-4"},
    logger=None
)

# Test generation
response = client.generate_response(
    prompt="Test prompt",
    system_prompt="You are a helpful assistant."
)

print(response)
```
