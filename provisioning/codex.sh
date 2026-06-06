#!/bin/bash
# Install OpenAI's Codex.
set -euxo pipefail

tool='    "npm:@openai/codex" = "latest"'
echo "$tool" >> .config/mise/config.toml

mise install
