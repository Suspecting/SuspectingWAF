# Contributing to SuspectingWAF

Hey, thanks for considering contributing. We appreciate it.

## How to contribute

### Reporting bugs

If you find a bug, please open an issue on GitHub. Include as much detail as you can:
- What you were doing when it happened
- What you expected to happen
- What actually happened
- Your environment (OS, Node version, Docker version if applicable)
- Relevant logs (check `data/logs/` or `docker compose logs`)

### Suggesting features

Open an issue with the `enhancement` label. Describe what you want and why. We're open to ideas but can't promise we'll implement everything.

### Pull requests

1. Fork the repo
2. Create a branch from `main` (`git checkout -b fix/whatever`)
3. Make your changes
4. Test your changes (`npm test`)
5. Commit with a clear message
6. Push and open a PR

Keep PRs focused. One feature or fix per PR. Don't mix unrelated changes.

### Code style

Nothing fancy. Just keep it consistent with what's already there:
- 2 space indentation
- Single quotes for strings
- Semicolons at the end of statements
- Use `const` and `let`, never `var`
- Meaningful variable names, no single letters (except loop counters, those are fine)

### Detection rules

If you want to add a new detection rule:
1. Create a new file in `src/engine/rules/`
2. Export a `check(req)` function that returns `{ blocked, rule, detail, severity }`
3. Register it in `src/engine/inspector.js`
4. Add tests in `tests/engine/`
5. Document it in `docs/detection-engine.md`

### Documentation

Docs live in `docs/`. Write like you're explaining to a friend, not writing a textbook. Keep it practical.

## Code of Conduct

Don't be a jerk. That's it. Treat people with respect, assume good intent, and focus on making the project better.

## Questions?

Open a discussion on GitHub or reach out via issues. We don't bite.
