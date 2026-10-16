"""Public CLI must not promote artifact/caller keys to production provenance."""
from __future__ import annotations

import json

import pytest

from conftest import audit_bundle, keypair, linear_entries, write_json, write_signed_export
from test_export_trust_root import _pack


def _synthetic_export(tmp_path):
    private, public, key_id = keypair()
    export, manifest = write_signed_export(
        tmp_path,
        audit_bundle(linear_entries([("synthetic.test_event", {})])),
        export_private_key=private, export_public_key=public, export_key_id=key_id,
    )
    keys = write_json(tmp_path / "caller-keys.json", {"keys": [{
        "key_id": key_id, "public_key": public, "purpose": "export_signing", "status": "active",
    }]})
    return export, manifest, keys, public


@pytest.mark.parametrize("mode", ["self-attested", "caller-manifest", "explicit-key", "signed-manifest-custom-root"])
def test_export_cli_truthfully_labels_trust_in_human_and_json(tmp_path, run_cli, mode):
    if mode == "signed-manifest-custom-root":
        export, manifest, keys, root = _pack(tmp_path)
        flags = ["--key-manifest", str(keys), "--trust-root", str(root)]
    else:
        export, manifest, keys, public = _synthetic_export(tmp_path)
        flags = {
            "self-attested": ["--self-attested"],
            "caller-manifest": ["--key-manifest", str(keys)],
            "explicit-key": ["--expected-public-key", public],
        }[mode]
    argv = ["export", str(export), str(manifest), *flags]
    machine = run_cli(*argv, "--json")
    human = run_cli(*argv)
    report = json.loads(machine.stdout)
    assert machine.returncode == human.returncode == 0
    assert report["ok"] is True
    assert "Keel production trust root" not in human.stdout
    source = report["artifact"]["trust_source"]
    if mode == "self-attested":
        assert source == "self-attested (embedded public_key)"
        assert "Trust mode: Self-attested (embedded key only)" in human.stdout
        assert "Does not prove Keel signed this artifact." in human.stdout
    else:
        assert source.startswith(("key manifest (", "user-supplied"))
        assert "Trust mode: Pinned key" in human.stdout


@pytest.mark.parametrize("mode", ["self-attested", "caller-manifest", "explicit-key"])
def test_trust_label_repair_preserves_tamper_rejection(tmp_path, run_cli, mode):
    export, manifest, keys, public = _synthetic_export(tmp_path)
    export.write_text(export.read_text() + " ")
    flags = {
        "self-attested": ["--self-attested"],
        "caller-manifest": ["--key-manifest", str(keys)],
        "explicit-key": ["--expected-public-key", public],
    }[mode]
    result = run_cli("export", str(export), str(manifest), *flags, "--json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False


def test_unpinned_signed_manifest_still_rejected(tmp_path, run_cli):
    export, manifest, keys, _ = _pack(tmp_path)
    result = run_cli("export", str(export), str(manifest), "--key-manifest", str(keys), "--json")
    assert result.returncode == 1
    assert json.loads(result.stdout)["ok"] is False


def test_bundled_root_source_remains_distinct_from_caller_manifest():
    from keel_verifier import verifier
    entries = verifier._load_key_manifest(str(verifier.DEFAULT_TRUST_ROOT_PATH))
    entry = next(e for e in entries if e.get("purpose") == "export_signing")
    public, source, error = verifier._resolve_trust_key(
        artifact_pub=None, artifact_key_id=entry["key_id"], purpose="export_signing",
        expected_public_key=None, public_key_url=None,
        key_manifest_source=str(verifier.DEFAULT_TRUST_ROOT_PATH),
    )
    assert error is None
    assert public == entry["public_key"]
    assert source.startswith("bundled Keel production trust root (")


def test_legacy_embedded_report_never_means_production():
    from keel_verifier.report_render import _trust_mode, load_presentation_registry
    registry = load_presentation_registry()
    assert _trust_mode({"artifact": {"trust_source": "embedded"}}, None, registry)["id"] == "self_attested"
    assert _trust_mode({"artifact": {"trust_source": "key manifest (caller)"}}, None, registry)["id"] == "pinned"


def test_self_attested_cli_still_verifies_valid_synthetic_chain(tmp_path, run_cli):
    export, manifest, _, _ = _synthetic_export(tmp_path)
    result = run_cli("export", str(export), str(manifest), "--self-attested", "--walk-events", "--json")
    report = json.loads(result.stdout)
    assert result.returncode == 0, report
    assert report["artifact"]["trust_source"] == "self-attested (embedded public_key)"
    claims = {c["name"]: c["verdict"] for c in report["claims"]}
    assert claims["export.integrity.v1"] == "supported"
    assert claims["governance_chain.local_continuity.v1"] == "supported"
