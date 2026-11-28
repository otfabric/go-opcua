#!/usr/bin/env bash
#
# Downloads the OPC UA schema files of the OPC Foundation UA-Nodeset
# repository at one commit and records them in schema/manifest.json: per
# input the upstream path, the commit, the SHA-256 and, for a NodeSet, its
# Models with their RequiredModels. The list of inputs is in
# internal/cmd/schemamanifest/manifest.go.
#
#   ./schema/update-schema.sh            # the pinned commit of the manifest
#   ./schema/update-schema.sh latest     # a branch, tag or commit
#
# Without an argument it downloads the pinned commit again, which must give
# no diff. With another ref it moves the pin; then regenerate the code with
# `make gen` and review the generated diff. The download fails unless the
# RequiredModels of every vendored NodeSet are satisfied (OPC 10000-6 §F.2).
# Set GH_TOKEN to raise the GitHub API rate limit.

set -o errexit
set -o nounset
set -o pipefail

script_dir=$(cd "$(dirname "$0")" && pwd)
cd "${script_dir}/.."

exec go run ./internal/cmd/schemamanifest update -ref "${1:-}"
