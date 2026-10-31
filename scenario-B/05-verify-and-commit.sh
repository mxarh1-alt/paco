#!/usr/bin/env bash
set +x
set -Eeuo pipefail
kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
exec bash "$kit/common/engine.sh" B-commit "$@"
