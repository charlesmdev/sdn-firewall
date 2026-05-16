#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

uv python install 3.9
uv venv --python 3.9 .venv

.venv/bin/python -m pip install --upgrade "pip<24" "setuptools<58" "wheel<0.38"
.venv/bin/python -m pip install --no-build-isolation -r requirements-ryu.txt

RYU_WSGI="$("$ROOT_DIR/.venv/bin/python" -c "import ryu, os; print(os.path.join(os.path.dirname(ryu.__file__), 'app', 'wsgi.py'))")"
perl -0pi -e 's/class _AlreadyHandledResponse\(Response\):\n    # XXX: Eventlet API should not be used directly\.\n    from eventlet\.wsgi import ALREADY_HANDLED\n    _ALREADY_HANDLED = ALREADY_HANDLED/class _AlreadyHandledResponse(Response):\n    # Compatibility for Eventlet versions that removed ALREADY_HANDLED.\n    _ALREADY_HANDLED = object()/s' "$RYU_WSGI"

"$ROOT_DIR/.venv/bin/ryu-manager" --version
echo "Ryu environment ready: $ROOT_DIR/.venv"
