# Native action fixtures (NAE M1)

Test data only. Every key here is a throwaway test key; only public keys are stored.

## keel-api vectors (byte-identical copies)

Copied with `git show <sha>:<path>` from keel-api branch `nae-m1-api-0ce40a` at
`2923d80fe84b119e64ccf08a99f280f5c208c534` (interface `nae-m1-interface/1.3.1`).

| File | Source path | Introduced in | sha256 |
|---|---|---|---|
| `native_action_golden_vectors_v1.json` | `tests/fixtures/native_action_golden_vectors_v1.json` | `54bee92b7` | `4e4a6717f1c0a137e73ee808473d4616571c4cbab5feeb1b6625272767cb9db6` |
| `native_action_pack_vectors_v1.json` | `tests/fixtures/native_action_pack_vectors_v1.json` | `4239a809f` | `6ebad46d643030344e19a46b3dc78eadb21035a46c7290ae324d89e7bdf1f2e8` |

The reference implementation these verdicts match is keel-api
`app/services/native_actions/evidence.py::check_native_action_pack`. At `2923d80fe` the
file's sha256 is `c1db2998d8d27618c9e9f11f5cfd9dee7d6beb0ddf8537f638322619245da1ad`. At
`27cae1c28` the vector files are byte-identical and `check_native_action_pack` is unchanged;
only the pack builder changed, to emit closure events per action in chain order.
`tests/test_native_action_v1.py` asserts the two digests above, so a refresh is explicit.

## `candidate/` (exported by a local keel-api candidate)

A clean clone of keel-api at `27cae1c28` (interface `nae-m1-interface/1.4.0`) ran locally.
Each run had a fresh PostgreSQL 17 database, the API on 127.0.0.1:8472 with the
in-process gateway double and fake GitHub, and keys generated for the session only.
Both lifecycles went through the real routes. The packs were downloaded from
`GET /v1/permits/{permit_id}/native-action-pack` and unzipped as-is.

`review_run/` (policy requires review): pair; propose (`review_pending`); dashboard
approval with the dev step-up; resume (`upstream_reported_success`, PR #1); a second resume
with no new effect.

- `reviewed_permit/`: the proposal Permit `b7f420f3-5f4c-4126-b204-3ade8e11d159`
  (action `01a1c10f-3c64-7f30-9ea6-96b2393673cb`). It verifies.
- `execution_permit/`: the review-resume execution Permit
  `dc5ea6d5-23e5-4a72-af55-a3ec82524bbd`.
- `execution_permit_signed_decision.json`: that Permit's signed `permit.decision.v1` capability,
  copied from its `/artifact/download` body.

`allow_run/` (policy allows): pair; propose (`allowed_eligible`, no Permit yet); resume 2 s
later (`upstream_reported_success`, PR #1; this is the 1.4.0 later-second fix); a second
resume with no new effect.

- `allowed_permit/`: the dispatch Permit `10357caf-ff73-476a-a8b9-be8b01bdcefa`
  (idempotency `mcp_call:native:dispatch:<hex>`).
- `allowed_permit_signed_decision.json`: its signed decision, taken from its artifact.

Both dispatch Permits are signed with a `final_request_hash`. keel-api's proof bundle omits
such decisions (`build_permit_decision_capability` without
`allow_final_request_binding=True`), so their packs fail `native.evidence_incomplete` here
and in the keel-api reference. This is an open, gate-blocking interface question. The
`*_signed_decision.json` files let the tests check the pack shape the fix would emit.

`instance-root.json` (one per run) is the candidate's export-signing public key. It pins the
signer of the packs' `key_manifest.json` through `--trust-root`.

The files hold no tokens, handles, secrets, PR title or body, or repository plaintext
(checked before commit).
