# Contributing to Automated IR & Threat Intelligence Platform

Thank you for your interest in contributing! This document outlines the process for contributing to this project.

## Code of Conduct
This project adheres to the [Contributor Covenant Code of Conduct](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

## How to Contribute

### Reporting Issues
- Use GitHub Issues to report bugs or request features
- Include: environment details, steps to reproduce, expected vs actual behaviour

### Pull Requests
1. Fork the repository
2. Create a feature branch: `git checkout -b feat/your-feature`
3. Follow [Conventional Commits](https://www.conventionalcommits.org/) for commit messages
4. Add tests for new functionality
5. Update documentation as needed
6. Open a PR against `main`

## Development Setup
```bash
git clone https://github.com/ChandraVerse/automated-ir-threat-intelligence-platform
cd automated-ir-threat-intelligence-platform
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp config/config.example.yml config/config.yml
```

## Project Structure
See `README.md` for the full directory structure and module descriptions.

## Style Guide
- Python: PEP 8, type hints required, docstrings on all public methods
- YAML playbooks: 2-space indent, comments required for each step
- Tests: pytest, minimum 80% coverage for new modules
