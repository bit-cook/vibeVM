#!/bin/bash
# Install Google's Gemini.
set -euxo pipefail

# Set this environment variable to prevent the Gemini CLI from failing to identify the sandbox command
echo "export GEMINI_SANDBOX=false" >> .bashrc

tool='    "npm:@google/gemini-cli" = "latest"'
echo "$tool" >> .config/mise/config.toml

mise install
