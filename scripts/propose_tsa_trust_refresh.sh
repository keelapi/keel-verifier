#!/usr/bin/env bash
# Commit a proven TSA trust refresh to one standing branch and propose it for
# review. Called by .github/workflows/tsa-trust-maintenance.yml only after the
# refreshed bundle has passed the full proof.
#
# The branch is replaced on every run instead of a new branch being created,
# so failed or superseded proposals do not accumulate. It only ever holds
# generated trust material this job proved, so replacing it discards nothing a
# reviewer could rely on.
#
# When repository policy stops the workflow token from opening pull requests
# ("Allow GitHub Actions to create and approve pull requests" is off), the
# proposal is filed as one standing issue that links the ready pull request.
# Either way a person opens and merges trust material, never this job.
#
# Environment:
#   TSA_REFRESH_BRANCH  standing branch (default: chore/tsa-trust-refresh)
#   TSA_DIFF_SUMMARY    markdown summary of the change (default: /tmp/tsa-diff.md)
#   GITHUB_SERVER_URL, GITHUB_REPOSITORY  set by Actions, for the compare link
#   GH_TOKEN            token used by gh
set -euo pipefail

BRANCH="${TSA_REFRESH_BRANCH:-chore/tsa-trust-refresh}"
DIFF_SUMMARY="${TSA_DIFF_SUMMARY:-/tmp/tsa-diff.md}"
PR_TITLE="chore: refresh release-pinned TSA CRL snapshots"
ISSUE_TITLE="TSA trust refresh ready for review"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

git config user.name "keel-tsa-maintenance"
git config user.email "noreply@keelapi.com"
git checkout -B "${BRANCH}"
git add -A
printf '%s\n' \
  'chore: refresh release-pinned TSA CRL snapshots' \
  '' \
  'Scheduled maintenance. Each CRL was accepted only after its issuer matched' \
  'the vendored issuer certificate and its signature verified against that' \
  "certificate's public key. Coupled real-crypto receipt fixtures were" \
  're-minted so their fixed genTime falls inside the new CRL window.' \
  '' \
  'Proposed for review; trust material is not merged automatically.' \
  > "${WORK}/commit.txt"
git commit -F "${WORK}/commit.txt"
git push --force origin "HEAD:refs/heads/${BRANCH}"

{
  echo 'Scheduled refresh of the release-pinned TSA CRL snapshots.'
  echo
  if [ -f "${DIFF_SUMMARY}" ]; then
    cat "${DIFF_SUMMARY}"
    echo
  fi
  echo '### Why this is safe to review quickly'
  echo
  echo '- A CRL entered the bundle only after its issuer matched the **vendored**'
  echo '  issuer certificate and its signature verified against that public key.'
  echo '  A wrong URL, stale mirror, or poisoned response cannot pass.'
  echo '- The full verifier suite, Ruff, the historical compatibility corpus, and'
  echo '  the TSA real-crypto tests ran green against the refreshed bundle before'
  echo '  this PR opened.'
  echo '- This job never merges. A human merges trust material.'
} > "${WORK}/pr-body.md"

existing_pr="$(gh pr list --base main --head "${BRANCH}" --state open \
  --json number --jq '.[0].number // empty')"
if [ -n "${existing_pr}" ]; then
  if ! gh pr edit "${existing_pr}" --body-file "${WORK}/pr-body.md"; then
    echo "::warning::Could not update the description of #${existing_pr}; its branch already holds the new refresh."
  fi
  echo "Refreshed the open review pull request #${existing_pr}."
  exit 0
fi

if gh pr create --base main --head "${BRANCH}" \
  --title "${PR_TITLE}" \
  --body-file "${WORK}/pr-body.md"; then
  exit 0
fi

compare_url="${GITHUB_SERVER_URL:-https://github.com}/${GITHUB_REPOSITORY:-keelapi/keel-verifier}/compare/main...${BRANCH}?expand=1"
{
  echo "A proven TSA trust refresh is waiting on branch \`${BRANCH}\`, but this"
  echo 'workflow is not allowed to open pull requests in this repository.'
  echo
  echo "**Open the review pull request:** ${compare_url}"
  echo
  echo "Use the title \`${PR_TITLE}\` and add \`Closes #<this issue>\` to its description."
  echo
  cat "${WORK}/pr-body.md"
} > "${WORK}/issue-body.md"

existing_issue="$(gh issue list --state open --search "\"${ISSUE_TITLE}\" in:title" \
  --json number,title \
  --jq "map(select(.title == \"${ISSUE_TITLE}\")) | .[0].number // empty")"
if [ -n "${existing_issue}" ]; then
  gh issue comment "${existing_issue}" --body-file "${WORK}/issue-body.md"
else
  gh issue create --title "${ISSUE_TITLE}" --body-file "${WORK}/issue-body.md"
fi
echo "::warning::This workflow may not open pull requests here; the proven refresh is linked from the '${ISSUE_TITLE}' issue: ${compare_url}"
