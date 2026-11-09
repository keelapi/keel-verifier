# Native action fixtures (NAE M1)

Test data only. Every key here is a throwaway test key; only public keys are stored.

## keel-api vectors (byte-identical copies)

Copied with `git show <sha>:<path>` from keel-api (branch `nae-m1-api-0ce40a`).

| File | Source path | Source commit | sha256 |
|---|---|---|---|
| `native_action_golden_vectors_v1.json` | `tests/fixtures/native_action_golden_vectors_v1.json` | `54bee92b7`; byte-identical at `24177dd8d` | `4e4a6717f1c0a137e73ee808473d4616571c4cbab5feeb1b6625272767cb9db6` |
| `native_action_pack_vectors_v1.json` | `tests/fixtures/native_action_pack_vectors_v1.json` | `24177dd8d` (interface 1.5.0; regenerated) | `4f144367fa259c77d21293c42e6c6b442f20b63195382378cff5d3558aec067e` |

The reference implementation these verdicts match is keel-api
`app/services/native_actions/evidence.py::check_native_action_pack` at `24177dd8d` (file
sha256 `ba46c6a82f8caf3e139952912517916d498136a635448dd28f397478c1a8aa48`). That version
refuses malformed exports instead of raising. `tests/test_native_action_v1.py` asserts both
vector digests above, so a refresh is explicit.

## `candidate/` (exported by a local keel-api candidate)

A clean clone of keel-api at `24177dd8d` (interface `nae-m1-interface/1.5.0`) ran locally.
Each run had a fresh PostgreSQL 17 database, the API on 127.0.0.1:8472 with the
in-process gateway double and fake GitHub, and keys generated for the session only.
Both lifecycles went through the real routes. The packs were downloaded from
`GET /v1/permits/{permit_id}/native-action-pack` and unzipped as-is. Nothing is simulated.

`review_run/` (policy requires review): pair; propose (`review_pending`); dashboard
approval with the dev step-up (attestation `fe3928fe-…`); resume
(`upstream_reported_success`, PR #1); a second resume with no new effect.

- `reviewed_permit/`: the proposal Permit `20d600de-1a1e-40f0-9b25-917543c1de43` (action
  `01a1c11b-358f-7da9-b969-f63526b90e6f`). Its signed decision has no final-request binding.
- `execution_permit/`: the review-resume execution Permit
  `e2e35399-c3f0-4c1a-af53-2e2eb25c93fd`. Its signed decision carries the
  `final_request_hash` that `dispatch_started` names.

`allow_run/` (policy allows): pair; propose (`allowed_eligible`, no Permit yet); resume 2 s
later (`upstream_reported_success`, PR #1); a second resume with no new effect.

- `allowed_permit/`: the dispatch Permit `d3bbd9fa-4b83-43fb-bdba-c74093643ba5`
  (idempotency `mcp_call:native:dispatch:<hex>`), final-request bound.

All three packs verify: export integrity, `permit.decision.v1` and the native checks.
`instance-root.json` (one per run) is the candidate's export-signing public key. It pins the
signer of the packs' `key_manifest.json` through `--trust-root`.

The files hold no tokens, handles, secrets, PR title or body, or repository plaintext
(checked before commit).
