#!/usr/bin/env bash

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
REPO_ROOT=$(cd "${SCRIPT_DIR}/.." && pwd)
GO_HELPER_DIR="${REPO_ROOT}/helpers/vibe-usernet"

cd "${REPO_ROOT}"

if [[ -z "${MISE_SHELL:-}" ]]; then
  echo "error: mise must be activated before running scripts" >&2
  exit 1
fi

vibe_go_files() {
  find "${GO_HELPER_DIR}" -type f -name '*.go' -print | sort
}

vibe_shell_scripts() {
  find "${SCRIPT_DIR}" -maxdepth 1 -type f \
    \( -name '*.sh' -o -perm -111 \) -print | sort
}
