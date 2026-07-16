#!/usr/bin/env bash
set -euo pipefail

module="github.com/faustbrian/go-authorization"
apidiff_version="v0.0.0-20250218142911-aa4b98e5adaa" # gitleaks:allow
baseline="api/go-authorization.txt"
current="$(mktemp)"
report="$(mktemp)"
trap 'rm -f "${current}" "${report}"' EXIT

if [[ ! -f "${baseline}" ]]; then
    echo "missing API baseline: ${baseline}" >&2
    exit 1
fi

go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" \
    -m -w "${current}" "${module}"
go run "golang.org/x/exp/cmd/apidiff@${apidiff_version}" \
    -m -incompatible "${baseline}" "${current}" >"${report}"

if [[ -s "${report}" ]]; then
    echo "incompatible exported API changes:" >&2
    cat "${report}" >&2
    exit 1
fi
