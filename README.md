# Opengrep Skills

Agent skills for [Opengrep](https://github.com/opengrep/opengrep) -- the open-source static analysis engine.

Built on the [Agent Skills](https://agentskills.io) open standard, these skills work with Claude Code, OpenAI Codex, OpenCode, and [other compatible agents](https://agentskills.io/specification).

## Available Skills

| Skill | Description |
|-------|-------------|
| [opengrep](skills/opengrep/SKILL.md) | Pattern-based code search and security scanning with Opengrep |

## Installation

### Via the skills CLI (recommended)

```bash
npx skills add opengrep/skills
```

### Manual

Copy the `skills/` directory to your agent's skills path:

| Agent | Path |
|-------|------|
| Claude Code | `~/.claude/skills/` |
| OpenCode | `~/.config/opencode/skills/` |
| Other agents | `~/.agents/skills/` |

## Links

- [Opengrep](https://github.com/opengrep/opengrep)
- [Agent Skills standard](https://agentskills.io)

## License

[MIT](LICENSE)
