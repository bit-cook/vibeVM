#!/bin/bash
# Install Earendil's Pi.
set -euxo pipefail

tool='    "npm:@earendil-works/pi-coding-agent" = "latest"'
echo "$tool" >> .config/mise/config.toml

mise install
