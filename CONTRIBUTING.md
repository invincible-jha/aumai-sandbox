# Contributing to AumAI Sandbox

Thank you for your interest in contributing! This guide will help you get started.

## Getting Started

### Prerequisites
- Python 3.11+
- Git
- Make (optional, for convenience commands)

### Setup
```bash
git clone https://github.com/aumai/aumai-sandbox.git
cd aumai-sandbox
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

### Run Tests
```bash
pytest tests/ -v
```

### Run Linting
```bash
ruff check src/
mypy src/ --strict
```

## How to Contribute

### Good First Issues
New to the project? Start with issues labeled [`good first issue`](https://github.com/aumai/aumai-sandbox/labels/good%20first%20issue).

### Skill Levels
- Beginner (~30 min): Documentation fixes, typo corrections, test additions
- Intermediate (~2 hours): Bug fixes, small features, example additions
- Advanced (~1 day+): New features, performance optimization, architecture changes

### Pull Request Process
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Write tests for your changes
4. Ensure all tests pass (`pytest tests/ -v`)
5. Ensure linting passes (`ruff check src/ && mypy src/ --strict`)
6. Commit with conventional commits (`feat:`, `fix:`, `docs:`, `test:`)
7. Open a PR with a clear description

### PR Requirements
- [ ] Tests pass
- [ ] Linting passes (ruff + mypy strict)
- [ ] Test coverage maintained or improved
- [ ] Documentation updated if API changed
- [ ] Conventional commit messages

## Code Style
- **Formatter:** ruff format
- **Linter:** ruff check
- **Type checking:** mypy strict mode
- **Docstrings:** Google style
- **Line length:** 88 characters

## Community
- [Discord](https://discord.gg/aumai)
- [GitHub Discussions](https://github.com/aumai/aumai-sandbox/discussions)
- Monthly Contributor Call (first Tuesday of each month)

## Recognition
All contributors are recognized in CONTRIBUTORS.md and receive
AumAI contributor badges for their GitHub profile.
