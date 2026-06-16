#!/usr/bin/env bash
# Convenience runner: activates the venv, makes libdmtx discoverable, runs the CLI.
# Usage: ./try.sh path/to/document.pdf [--no-verify] [--keystore DIR] [--no-revocation]
set -euo pipefail
cd "$(dirname "$0")"
source .venv/bin/activate
export DYLD_LIBRARY_PATH="$(brew --prefix libdmtx 2>/dev/null)/lib:${DYLD_LIBRARY_PATH:-}"
export SETUPTOOLS_USE_DISTUTILS=local
python -m twoddoc.cli "$@"
