# Contributing to Claw

First off, thanks for taking the time to contribute! 🦞

## How Can I Contribute?

### Reporting Bugs

Before creating bug reports, please check existing issues to avoid duplicates. When creating a bug report, include:

- **Clear title** describing the issue
- **Steps to reproduce** the behavior
- **Expected behavior** vs what actually happened
- **Screenshots** if applicable
- **Environment details**: OS, Python version, tmux version

### Suggesting Features

Feature requests are welcome! Please:

- Use a **clear and descriptive title**
- Provide a **detailed description** of the proposed feature
- Explain **why this would be useful** to most users
- Include **mockups or examples** if possible

### Pull Requests

1. **Fork** the repo and create your branch from `main`
2. **Make your changes** with clear, concise commits
3. **Test** your changes thoroughly
4. **Update documentation** if needed
5. **Submit** a pull request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/YOUR_USERNAME/claw.git
cd claw

# Run locally
python3 claw.py

# Test on your phone
# Open http://<your-ip>:8080
```

## Code Style

- Follow PEP 8 for Python code
- Use meaningful variable and function names
- Add comments for complex logic
- Keep functions focused and small

## Commit Messages

- Use present tense ("Add feature" not "Added feature")
- Use imperative mood ("Move cursor to..." not "Moves cursor to...")
- Keep first line under 50 characters
- Reference issues and PRs when relevant

### Examples

```
Add dark mode toggle to settings

Fix terminal scroll on mobile Safari

Update README with Tailscale instructions

Close #123 - Handle empty tmux sessions gracefully
```

## Questions?

Feel free to open an issue with your question or reach out to the maintainers.

Thank you for contributing! 🙏
