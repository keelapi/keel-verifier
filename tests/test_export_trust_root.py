"""``export --trust-root`` verifies a proof pack with its own signed key manifest.

A Keel proof pack carries the instance's complete signed key manifest
(export, checkpoint, scope-state, permit-binding keys). Its signer must be
pinned. Production packs pin it through the bundled trust root; a
non-production instance is pinned with ``--trust-root``, which replaces only
that anchor and leaves every other check in place.
"""

from __future__ import annotations

import argparse
import base64
import json

from conftest import (
    keypair,
    permit_binding_key_id,
    write_json,
    write_signed_export,
)
from keel_verifier import verifier


def _entry(key_id: str, public_key: str, purpose: str) -> dict:
    return {
        "key_id": key_id,
        "algorithm": "ed25519",
        "public_key": public_key,
        "purpose": purpose,
        "status": "active",
        "valid_from": "2026-01-01T00:00:00Z",
        "valid_to": None,
    }


def _signed_key_manifest(tmp_path, *, signer_private, signer_key_id, keys):
    body = {
        "manifest_version": "keel.public_key_manifest.v1",
        "canonicalization_profile": "keel.canonical_json.payload.v1",
        "keys": keys,
    }
    digest = verifier._content_hash(verifier._manifest_signature_payload_bytes(body))
    signature = base64.b64encode(signer_private.sign(digest.encode("utf-8"))).decode("ascii")
    body["manifest_signature"] = {
        "signature_type": "ed25519.content_hash.v1",
        "purpose": "export_signing",
        "key_id": signer_key_id,
        "content_hash": digest,
        "signature": signature,
    }
    return write_json(tmp_path / "key_manifest.json", body)


def _pack(tmp_path):
    export_private, export_public, export_key_id = keypair()
    _binding_private, binding_public, _ = keypair()
    keys = [
        _entry(export_key_id, export_public, "export_signing"),
        _entry(export_key_id, export_public, "integrity_checkpoint"),
        _entry(export_key_id, export_public, "scope_state"),
        _entry(permit_binding_key_id(binding_public), binding_public, "permit_binding_signing"),
    ]
    key_manifest = _signed_key_manifest(
        tmp_path,
        signer_private=export_private,
        signer_key_id=export_key_id,
        keys=keys,
    )
    export_file, manifest = write_signed_export(
        tmp_path,
        {"bundle_type": "audit_export_bundle", "schema_version": 1, "records": []},
        export_private_key=export_private,
        export_public_key=export_public,
        export_key_id=export_key_id,
    )
    root = write_json(
        tmp_path / "instance-root.json",
        {"keys": [_entry(export_key_id, export_public, "export_signing")]},
    )
    return export_file, manifest, key_manifest, root


def _run(run_cli, *args):
    result = run_cli("export", "--json", *args)
    return result, json.loads(result.stdout)


def test_signed_pack_manifest_needs_a_pinned_signer(tmp_path, run_cli):
    export_file, manifest, key_manifest, _root = _pack(tmp_path)

    result, report = _run(
        run_cli, str(export_file), str(manifest), "--key-manifest", str(key_manifest)
    )

    assert result.returncode == 1
    assert report["ok"] is False
    assert "no unique active pinned trust key resolved" in report["error"]


def test_trust_root_pins_the_pack_manifest_signer(tmp_path, run_cli):
    export_file, manifest, key_manifest, root = _pack(tmp_path)

    result, report = _run(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--trust-root",
        str(root),
    )

    assert result.returncode == 0, result.stdout + result.stderr
    assert report["ok"] is True


def test_trust_root_for_another_signer_is_refused(tmp_path, run_cli):
    export_file, manifest, key_manifest, _root = _pack(tmp_path)
    _other_private, other_public, other_key_id = keypair()
    wrong_root = write_json(
        tmp_path / "wrong-root.json",
        {"keys": [_entry(other_key_id, other_public, "export_signing")]},
    )

    result, report = _run(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--trust-root",
        str(wrong_root),
    )

    assert result.returncode == 1
    assert report["ok"] is False


def test_tampered_pack_manifest_is_refused_under_its_trust_root(tmp_path, run_cli):
    export_file, manifest, key_manifest, root = _pack(tmp_path)
    tampered = json.loads(key_manifest.read_text(encoding="utf-8"))
    _attacker_private, attacker_public, _ = keypair()
    tampered["keys"][-1]["public_key"] = attacker_public
    key_manifest.write_text(json.dumps(tampered), encoding="utf-8")

    result, report = _run(
        run_cli,
        str(export_file),
        str(manifest),
        "--key-manifest",
        str(key_manifest),
        "--trust-root",
        str(root),
    )

    assert result.returncode == 1
    assert report["ok"] is False
    assert "content_hash" in report["error"]


def test_trust_root_override_does_not_outlive_the_call(tmp_path):
    export_file, manifest, key_manifest, root = _pack(tmp_path)

    def args(**extra):
        values = dict(
            export_file=str(export_file),
            manifest=str(manifest),
            key_manifest=str(key_manifest),
            key_manifest_url=None,
            expected_public_key=None,
            public_key=None,
            self_attested=False,
            offline=False,
            allow_unsigned=False,
            walk_events=False,
            verify_closure=False,
            as_json=True,
            trust_root=None,
        )
        values.update(extra)
        return argparse.Namespace(**values)

    assert verifier.verify_export_structured(args(trust_root=str(root))).ok is True
    assert verifier.verify_export_structured(args()).ok is False
