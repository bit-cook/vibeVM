#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/_common.sh"

usage() {
  echo "usage: ./scripts/test.sh [all|rust|go|shell]" >&2
  exit 64
}

run_rust() {
  cargo fmt --check
  cargo clippy --all-targets -- --deny warnings
  # TODO: write Rust tests
  # cargo test
}

run_go() {
  go_files=()
  while IFS= read -r file; do
    go_files+=("${file}")
  done < <(vibe_go_files)
  if [[ ${#go_files[@]} -eq 0 ]]; then
    return
  fi

  unformatted_go_files=()
  while IFS= read -r file; do
    unformatted_go_files+=("${file}")
  done < <(gofmt -l "${go_files[@]}")

  if [[ ${#unformatted_go_files[@]} -gt 0 ]]; then
    printf 'error: gofmt needed for:\n' >&2
    printf '  %s\n' "${unformatted_go_files[@]}" >&2
    exit 1
  fi

  (cd "${GO_HELPER_DIR}" && go vet ./...)

  # TODO: write Go tests
  # (cd "${GO_HELPER_DIR}" && go test ./...)
}

run_shell() {
  shell_scripts=()
  while IFS= read -r file; do
    shell_scripts+=("${file}")
  done < <(vibe_shell_scripts)
  if [[ ${#shell_scripts[@]} -eq 0 ]]; then
    return
  fi

  shellcheck_exclusions=(
    # SC2164: rely on set -e to stop scripts when cd fails.
    SC2164
  )
  shfmt --indent 2 --diff "${shell_scripts[@]}"
  shellcheck --exclude "$(
    IFS=,
    echo "${shellcheck_exclusions[*]}"
  )" --severity warning "${shell_scripts[@]}"
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
