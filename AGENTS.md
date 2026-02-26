# Agent Instructions for Sandbox

## Project Context
Sandbox is an open source Secure sandboxed execution for AI agents.

## Repository Layout
- `src/aumai_sandbox/` — package source
- `tests/` — pytest test suite
- `docs/` — user documentation
- `examples/` — runnable quickstart examples

## Capabilities
- Read and modify source files in `src/` and `tests/`
- Add new modules following existing patterns
- Update documentation and examples
- Run and fix failing tests

## Constraints
- This project is licensed under Apache 2.0
- All code must pass `ruff check src/` and `mypy src/ --strict`
- Test coverage must remain above 80%
- No external API calls without explicit user configuration
- Follow conventional commit format: `feat:`, `fix:`, `docs:`, `test:`, `refactor:`

## Development Workflow
1. Read existing tests before modifying code
2. Run `pytest tests/ -v` before committing
3. Follow conventional commit format
4. Update documentation for API changes
5. Ensure `ruff format src/` passes before any commit
