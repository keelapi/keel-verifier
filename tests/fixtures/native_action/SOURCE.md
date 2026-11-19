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
`app/services/native_actions/evidence.py::check_native_action_pack` at the same commit
(sha256 `c1db2998d8d27618c9e9f11f5cfd9dee7d6beb0ddf8537f638322619245da1ad`).
`tests/test_native_action_v1.py` asserts the two digests above, so a refresh is explicit.

## `candidate/` (exported by a local keel-api candidate)

A clone of keel-api at `2923d80fe` ran locally (fresh PostgreSQL 17 database, API on
127.0.0.1:8472, in-process gateway double with fake GitHub, keys generated for that run
only). One native lifecycle ran through the real routes: pair, propose (`review_pending`),
dashboard approval with the dev step-up, resume (`upstream_reported_success`, PR #1), and a
second resume with no new effect. Both packs were downloaded from
`GET /v1/permits/{permit_id}/native-action-pack` and unzipped as-is:

- `reviewed_permit/`: the native proposal Permit `eee6d99d-31c3-497a-8e5c-3d31c202d62a`
  (action `01a1c0fc-3344-7966-a490-aebd940cffb5`). It verifies.
- `execution_permit/`: the review-resume execution Permit
  `b87e7d76-070d-4660-9d14-4002c43b407b`. Its proof bundle has no `permit_decision`, so
  it fails `native.evidence_incomplete` here and in the keel-api reference. This is an open
  interface question.
- `instance-root.json`: the candidate's export-signing public key. It pins the signer of
  the packs' `key_manifest.json` through `--trust-root`.

The packs hold no tokens, handles, secrets, PR title or body, or repository plaintext
(checked before commit).
