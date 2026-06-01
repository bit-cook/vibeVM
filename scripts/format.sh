#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  echo "usage: ./scripts/format.sh [all|rust|go|shell]" >&2
  exit 64
}

run_rust() {
  cargo fmt
}

run_go() {
  go_files=()
  while IFS= read -r file; do
    go_files+=("${file}")
  done < <(vibe_go_files)
  if [[ ${#go_files[@]} -eq 0 ]]; then
    return
  fi

  gofmt -w "${go_files[@]}"
}

run_shell() {
  shell_scripts=()
  while IFS= read -r file; do
    shell_scripts+=("${file}")
  done < <(vibe_shell_scripts)
  if [[ ${#shell_scripts[@]} -eq 0 ]]; then
    return
  fi

  shfmt --indent 2 --write "${shell_scripts[@]}"
}

if [[ $# -gt 1 ]]; then
  usage
fi

case "${1:-all}" in
all)
  run_rust
  run_go
  run_shell
  ;;
rust)
  run_rust
  ;;
go)
  run_go
  ;;
shell)
  run_shell
  ;;
*)
  usage
  ;;
esac
