# VulnGuard LLM Integration Guide

This guide explains how to configure and use VulnGuard with various LLM providers for AI-powered security compliance analysis.

## Table of Contents

- [Overview](#overview)
- [Supported LLM Providers](#supported-llm-providers)
- [Configuration](#configuration)
- [Setup Instructions](#setup-instructions)
- [Usage Examples](#usage-examples)
- [Troubleshooting](#troubleshooting)

---

## Overview

VulnGuard supports AI-powered advisory services through multiple LLM providers. The AI advisor analyzes security compliance findings and provides safe, validated remediation recommendations.

### Key Features

- **Multiple Provider Support**: OpenAI, Anthropic, Local LLMs, and Mock for testing
- **Safety-First Design**: All AI output is validated against allow-lists and confidence thresholds
- **Fallback Mechanism**: Automatically falls back to rule-based responses if LLM is unavailable
- **Prompt Engineering**: Specialized prompts for security compliance analysis

---

## Supported LLM Providers

### 1. OpenRouter (Multi-Provider Gateway)

**Models**: OpenAI (GPT), Anthropic (Claude), Google (Gemini), Meta (Llama), and many more

**Pros**:
- Single API key for multiple providers
- Access to latest models from different companies
- Cost optimization through provider selection
- Unified interface

**Cons**:
- Requires API key
- Usage-based pricing
- Requires internet connection

**Recommended for**: Production environments wanting flexibility in provider/model selection

### 2. OpenAI (GPT Models)

**Models**: GPT-4, GPT-3.5 Turbo

**Pros**:
- High-quality reasoning and analysis
- Well-documented API
- Fast response times

**Cons**:
- Requires API key
- Usage-based pricing
- Requires internet connection

**Recommended for**: Production environments requiring high-quality analysis

### 3. Anthropic (Claude Models)

**Models**: Claude 3 Opus, Claude 3 Sonnet, Claude 3 Haiku

**Pros**:
- Excellent for security analysis
- Strong adherence to instructions
- Competitive pricing

**Cons**:
- Requires API key
- Usage-based pricing
- Requires internet connection

**Recommended for**: Production environments with focus on security analysis

### 4. Ollama (Local LLM API)

**Models**: LLaMA, Mistral, Falcon, and other Ollama-supported models

**Pros**:
- No API costs
- Works offline
- Privacy-preserving
- Fast inference on local hardware
- Easy to set up

**Cons**:
- Requires Ollama installation
- Limited to available models
- Requires local hardware resources

**Recommended for**: Air-gapped environments, privacy-sensitive deployments, testing

### 5. Local LLM (Transformers)

**Models**: LLaMA, Mistral, Falcon, and other Hugging Face models

**Pros**:
- No API costs
- No data leaves your network
- Works offline
- Privacy-preserving

**Cons**:
- Requires significant hardware (GPU recommended)
- Slower inference times
- More complex setup

**Recommended for**: Air-gapped environments, privacy-sensitive deployments

### 6. Mock (Testing)

**Purpose**: Testing and development

**Pros**:
- No API key required
- Deterministic responses
- Fast

**Cons**:
- Not for production use
- Limited analysis capabilities

**Recommended for**: Development and testing only

---

## Configuration

### Configuration File

LLM settings are configured in [`vulnguard/configs/agent/config.yaml`](../vulnguard/configs/agent/config.yaml):

```yaml
ai:
  enabled: true
  provider: "openai"  # Options: openai, anthropic, local, mock
  min_confidence_threshold: 0.7
  require_approval_for:
    - "CAT_I"
    - "CAT_II"
    - "critical"
  max_retries: 2
  timeout_seconds: 30
  
  # OpenAI Configuration
  openai:
    api_key: "${OPENAI_API_KEY}"
    model: "gpt-4-turbo-preview"
    api_endpoint: "https://api.openai.com/v1/chat/completions"
    max_tokens: 2000
    temperature: 0.3
  
  # Anthropic Configuration
  anthropic:
    api_key: "${ANTHROPIC_API_KEY}"
    model: "claude-3-opus-20240229"
    api_endpoint: "https://api.anthropic.com/v1/messages"
    max_tokens: 2000
    temperature: 0.3
  
  # Local LLM Configuration
  local:
    model_path: "/path/to/model"
    model_type: "llama"
    device: "auto"
    max_tokens: 2000
    temperature: 0.3
  
  # Mock Configuration
  mock:
    enabled: false
```

### Configuration Options

| Setting | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable AI advisor |
| `provider` | string | `openai` | LLM provider to use |
| `min_confidence_threshold` | float | `0.7` | Minimum confidence (0.0 - 1.0) |
| `max_retries` | integer | `2` | Maximum retry attempts |
| `timeout_seconds` | integer | `30` | Request timeout in seconds |
| `max_tokens` | integer | `2000` | Maximum response tokens |
| `temperature` | float | `0.3` | Sampling temperature (0.0 - 1.0) |

---

## Setup Instructions

### OpenAI Setup

1. **Get API Key**:
   - Visit https://platform.openai.com/api-keys
   - Create a new API key
   - Copy the key

2. **Set Environment Variable**:
   ```bash
   export OPENAI_API_KEY=sk-your-api-key-here
   ```

3. **Configure VulnGuard**:
   ```yaml
   ai:
     provider: "openai"
     openai:
       api_key: "${OPENAI_API_KEY}"
       model: "gpt-4-turbo-preview"
   ```

4. **Test Configuration**:
   ```bash
   python -m vulnguard.main list-rules
   ```

### Anthropic Setup

1. **Get API Key**:
   - Visit https://console.anthropic.com/
   - Create a new API key
   - Copy the key

2. **Set Environment Variable**:
   ```bash
   export ANTHROPIC_API_KEY=sk-ant-your-api-key-here
   ```

3. **Configure VulnGuard**:
   ```yaml
   ai:
     provider: "anthropic"
     anthropic:
       api_key: "${ANTHROPIC_API_KEY}"
       model: "claude-3-opus-20240229"
   ```

4. **Test Configuration**:
   ```bash
   python -m vulnguard.main list-rules
   ```

### Local LLM Setup

1. **Install Dependencies**:
   ```bash
   pip install transformers torch accelerate
   ```

2. **Download Model**:
   - Visit https://huggingface.co/models
   - Choose a model (e.g., LLaMA 2, Mistral)
   - Download the model files

3. **Set Environment Variables**:
   ```bash
   export LOCAL_LLM_MODEL_PATH=/path/to/your/model
   export LOCAL_LLM_MODEL_TYPE=llama
   export LOCAL_LLM_DEVICE=auto
   ```

4. **Configure VulnGuard**:
   ```yaml
   ai:
     provider: "local"
     local:
       model_path: "${LOCAL_LLM_MODEL_PATH}"
       model_type: "${LOCAL_LLM_MODEL_TYPE}"
       device: "${LOCAL_LLM_DEVICE}"
   ```

5. **Test Configuration**:
   ```bash
   python -m vulnguard.main list-rules
   ```

### Mock Setup (Testing)

1. **Configure VulnGuard**:
   ```yaml
   ai:
     provider: "mock"
     mock:
       enabled: true
   ```

2. **Test Configuration**:
   ```bash
   python -m vulnguard.main scan --rule-id cis_1_1_1
   ```

---

## Usage Examples

### Basic Scan with AI Advisory

```bash
# Scan all rules with AI advisory
vulnguard scan

# Scan specific rule with AI advisory
vulnguard scan --rule-id cis_1_1_1

# Scan with custom output format
vulnguard scan --format text --output report.txt
```

### Remediation with AI Advisory

```bash
# Dry-run remediation (recommended first)
vulnguard remediate --mode dry-run

# Commit remediation (after review)
vulnguard remediate --mode commit

# Force remediation (skip approval)
vulnguard remediate --mode commit --force
```

### Environment Variables

Using `.env` file:

```bash
# Copy example file
cp .env.example .env

# Edit with your values
nano .env

# Load environment variables
source .env

# Run VulnGuard
vulnguard scan
```

---

## Troubleshooting

### Common Issues

#### Issue: "API key not found"

**Solution**:
```bash
# Check if environment variable is set
echo $OPENAI_API_KEY

# Set environment variable
export OPENAI_API_KEY=sk-your-key-here

# Or add to .env file
echo "OPENAI_API_KEY=sk-your-key-here" >> .env
```

#### Issue: "Failed to initialize LLM client"

**Solution**:
- Check configuration file syntax
- Verify provider name is correct (openai, anthropic, local, mock)
- Check API key format
- Ensure dependencies are installed

#### Issue: "AI confidence below threshold"

**Solution**:
- Lower the `min_confidence_threshold` in config
- Review AI output quality
- Consider using a different model

#### Issue: "Local LLM requires transformers and torch"

**Solution**:
```bash
# Install required dependencies
pip install transformers torch accelerate

# For GPU support
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
```

#### Issue: "CUDA out of memory"

**Solution**:
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

---

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

---

## Advanced Configuration

### Custom Prompts

Modify prompts in [`vulnguard/pkg/advisor/prompts.py`](../vulnguard/pkg/advisor/prompts.py):

```python
class CompliancePrompts:
    SYSTEM_PROMPT = """Your custom system prompt here..."""
```

### Custom Validation

Modify validation rules in [`vulnguard/pkg/advisor/advisor.py`](../vulnguard/pkg/advisor/advisor.py):

```python
DEFAULT_COMMAND_ALLOWLIST = [
    r'^your-custom-pattern-here$'
]
```

### Multiple Providers

Configure multiple providers for failover:

```python
# In your custom code
providers = [
    create_llm_client("openai", openai_config),
    create_llm_client("anthropic", anthropic_config)
]

# Try each provider in order
for provider in providers:
    try:
        response = provider.generate_response(prompt)
        break
    except Exception:
        continue
```

---

## Performance Tuning

### Temperature Settings

- **0.0 - 0.3**: More deterministic, conservative
- **0.4 - 0.7**: Balanced creativity and consistency
- **0.8 - 1.0**: More creative, less predictable

**Recommended**: 0.3 for security compliance

### Token Limits

- **Lower limits** (500-1000): Faster, cheaper, less detailed
- **Medium limits** (1000-2000): Balanced
- **Higher limits** (2000-4000): Slower, more expensive, more detailed

**Recommended**: 2000 for comprehensive analysis

### Timeout Settings

- **Short** (10-20s): Faster failures, may timeout on complex queries
- **Medium** (30-60s): Balanced
- **Long** (60-120s): Slower failures, handles complex queries

**Recommended**: 30s for most use cases

---

## Support

For issues or questions:
- Review [ARCHITECTURE.md](ARCHITECTURE.md) for system design
- Review [CONFIGURATION.md](CONFIGURATION.md) for general configuration
- Check logs in `/var/log/vulnguard/audit.log`
- Enable debug logging for detailed troubleshooting
