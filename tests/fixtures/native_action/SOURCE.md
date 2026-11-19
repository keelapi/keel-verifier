# Native action fixtures (NAE M1)

Test data only. Every key here is a throwaway test key; only public keys are stored.

## keel-api vectors (byte-identical copies)

Copied with `git show <sha>:<path>` from keel-api (branch `nae-m1-api-0ce40a`).

| File | Source path | Source commit | sha256 |
|---|---|---|---|
| `native_action_golden_vectors_v1.json` | `tests/fixtures/native_action_golden_vectors_v1.json` | `54bee92b7`; byte-identical at `24177dd8d` | `4e4a6717f1c0a137e73ee808473d4616571c4cbab5feeb1b6625272767cb9db6` |
| `native_action_pack_vectors_v1.json` | `tests/fixtures/native_action_pack_vectors_v1.json` | `24177dd8d` (interface 1.5.0; regenerated); byte-identical at `771d1cdff` | `4f144367fa259c77d21293c42e6c6b442f20b63195382378cff5d3558aec067e` |
| `native_action_pack_crash_cases_v1.json` | `tests/fixtures/native_action_pack_crash_cases_v1.json` | `70eab473f`; byte-identical at `771d1cdff` | `493eae3e9a34fb6aeb583c4cb52e9b9909300f2038bc0db076dd755d12743b4f` |

The reference implementation these verdicts match is keel-api
`app/services/native_actions/evidence.py::check_native_action_pack` at `24177dd8d` (file
sha256 `ba46c6a82f8caf3e139952912517916d498136a635448dd28f397478c1a8aa48`). That version
refuses malformed exports instead of raising. The file is byte-identical at `771d1cdff`
(interface 1.7.1). The crash cases are 18 single-field mutations of the vectors' `base_export`
that crashed the reference at `27cae1c28`; keel-api pins them as negatives, and the expected
verdicts are the ones both implementations now return. `tests/test_native_action_v1.py` asserts both
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

`expired_run/` (keel-api `771d1cdff`, interface 1.7.1; same recipe, fresh database; policy
requires review with a 45 s approval window): pair; propose (`review_pending`); dashboard approval
with the dev step-up; wait past the window; status and two resumes all answer `expired`; the
fake GitHub saw no `POST`.

- `expired_permit/`: the reviewed Permit `0114f26c-7690-4d16-9d40-72b1dc254931` (action
  `01a1c164-b7cb-7c4b-882d-d7d12c4056c3`), Permit status `expired`. Its closure events are
  `proposed` and `review_decided` only. The pack verifies.

Same checks before commit: no tokens, handles, secrets, PR title or body.
