"""The shipped export quickstart sends the canonical project-authenticated body.

Run the actual README curl command through a local public-HTTP oracle. This
catches customer instructions that would fail strict request validation before
export generation or offline verification can begin.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


def test_readme_export_curl_requests_a_full_audit_for_the_authenticated_project():
    readme = (Path(__file__).resolve().parents[1] / "README.md").read_text()
    section = readme.split("## Obtaining a Signed Export", 1)[1]
    command = re.search(r"```bash\n(curl .*?)\n```", section, re.S).group(1)
    observations = []

    class PublicExportOracle(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            accepted = (
                self.path == "/v1/compliance/exports?include_chain_entries=true"
                and self.headers.get("Authorization") == "Bearer customer-project-key"
                and body == {"export_type": "full_audit", "format": "json"}
            )
            observations.append((body, accepted))
            self.send_response(202 if accepted else 422)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "queued" if accepted else "invalid"}).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), PublicExportOracle)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        local_command = command.replace(
            "https://api.keelapi.com", f"http://127.0.0.1:{server.server_port}"
        )
        result = subprocess.run(
            ["/bin/sh", "-c", local_command],
            env={**os.environ, "KEEL_API_KEY": "customer-project-key"},
            text=True,
            capture_output=True,
            timeout=10,
        )
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)
    assert result.returncode == 0, result.stderr
    assert observations == [({"export_type": "full_audit", "format": "json"}, True)]
    assert json.loads(result.stdout)["status"] == "queued"
