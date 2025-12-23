#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

cd "$PROJECT_ROOT"

VENV_DIR=".venv-testsuite"

python3 -m venv "$VENV_DIR"
source "$VENV_DIR/bin/activate"

pip install --upgrade pip
pip install -r requirements.txt

echo
echo "Testsuite venv ready."
echo "To use it:"
echo "  cd \"$PROJECT_ROOT\""
echo "  source $VENV_DIR/bin/activate"
echo "  pytest tests/integration -vv"
