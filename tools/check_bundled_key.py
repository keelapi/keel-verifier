"""Verify that the bundled trust root matches the live Keel endpoint.

Run from the repo root:

    python tools/check_bundled_key.py

Exit 0 if the bundled key at ``keel_verifier/keys/keel_checkpoint.pub.json``
matches the value served by ``https://api.keelapi.com/v1/integrity/checkpoint-public-key``.
Exit 1 on mismatch (catches silent swap of the bundled file, or an
unsynced key rotation that would render real Keel checkpoints
unverifiable by the default ``--offline``-equivalent path).
Exit 2 on operational failure (network unreachable, malformed response).

Run from CI on every push so the trust root cannot drift unnoticed.
"""

from __future__ import annotations

import json
import sys
import urllib.request
from pathlib import Path

LIVE_URL = "https://api.keelapi.com/v1/integrity/checkpoint-public-key"
BUNDLED_PATH = (
    Path(__file__).resolve().parent.parent
    / "keel_verifier"
    / "keys"
    / "keel_checkpoint.pub.json"
)


def main() -> int:
    if not BUNDLED_PATH.exists():
        print(f"FAIL: bundled key not found at {BUNDLED_PATH}", file=sys.stderr)
        return 2

    try:
        bundled = json.loads(BUNDLED_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        print(f"FAIL: bundled key file is not valid JSON: {exc}", file=sys.stderr)
        return 2

    bundled_pub = bundled.get("public_key")
    bundled_kid = bundled.get("key_id")

    try:
        with urllib.request.urlopen(LIVE_URL, timeout=10) as resp:
            live = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        print(f"FAIL: could not fetch {LIVE_URL}: {exc}", file=sys.stderr)
        return 2

    live_pub = live.get("public_key")
    live_kid = live.get("key_id")

    if bundled_pub == live_pub and bundled_kid == live_kid:
        print(f"OK: bundled trust root matches {LIVE_URL}")
        print(f"  public_key: {bundled_pub}")
        print(f"  key_id:     {bundled_kid}")
        return 0

    print("FAIL: bundled trust root does NOT match the live endpoint.", file=sys.stderr)
    print(f"  bundled public_key: {bundled_pub}", file=sys.stderr)
    print(f"  live    public_key: {live_pub}", file=sys.stderr)
    print(f"  bundled key_id:     {bundled_kid}", file=sys.stderr)
    print(f"  live    key_id:     {live_kid}", file=sys.stderr)
    print(file=sys.stderr)
    print(
        "If the live key rotated, refresh the bundled file with:",
        file=sys.stderr,
    )
    print(f"  curl -fsS {LIVE_URL} > {BUNDLED_PATH.relative_to(BUNDLED_PATH.parent.parent.parent)}", file=sys.stderr)
    print(
        "Then commit the change. If you did not expect a rotation, "
        "investigate before refreshing.",
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
