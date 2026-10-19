# falcon-guardian-github-copilot-collector

Falcon Guardian collector for GitHub Copilot CLI.

## Usage

```json
{
  "version": 1,
  "hooks": {
    "UserPromptSubmit": [
      {
        "type": "command",
        "exec": "/path/to/falcon-guardian-github-copilot-collector"
      }
    ],
    "PreToolUse": [
      {
        "type": "command",
        "exec": "/path/to/falcon-guardian-github-copilot-collector"
      }
    ],
    "PostToolUse": [
      {
        "type": "command",
        "exec": "/path/to/falcon-guardian-github-copilot-collector"
      }
    ]
  }
}
```

## Configuration

| Flag | Env | Default |
|---|---|---|
| `--token` | `CS_AIDR_TOKEN` | required |
| `--base-url` | `CS_AIDR_BASE_URL` | `https://api.crowdstrike.com/aidr/aiguard` |
| `--timeout <secs>` | | `30` |
| `--failure-mode <open\|closed>` | | `open` |
