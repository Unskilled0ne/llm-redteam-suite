# Contributing to LLM Red-Team Suite

Thank you for your interest in improving the LLM Red-Team Suite! We welcome contributions from the community, whether they are new adversarial payloads, enhanced guardrails, or integrations with other CI/CD tools.

## How to Contribute

1. **Fork the Repository:** Start by forking the repository and cloning it locally.
2. **Set Up Development Environment:** Run `python3 -m venv venv`, activate it, and run `pip install -r requirements.txt`. Install `pytest` for testing: `pip install pytest`.
3. **Run Tests:** Ensure all tests pass before developing by running `pytest tests/`.
4. **Develop:** Add your payloads to `redteam/payloads/` or improve guardrail modules. If modifying defensive code, add a corresponding test in the `tests/` directory.
5. **Submit a Pull Request:** Describe your changes thoroughly and link any relevant GitHub issues.

## Adding New Adversarial Payloads
If you discover a new jailbreak or prompt injection vector, please format it following the schema in `redteam/payloads/direct_injection.json` and categorize it under the correct OWASP LLM 2025 category.

## Code Style
Please adhere to PEP 8 standards for Python code.

Thank you for helping secure the AI ecosystem!
