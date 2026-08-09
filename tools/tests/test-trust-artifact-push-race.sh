#!/usr/bin/env bash
# Reproduce the deploy race in a scratch repo and prove the fix survives it.
#
# The real failure: two deploys queue, the second checks out its own sha, and by
# the time it pushes its trust artifacts the first run's release commit is
# already on main. A plain push dies non-fast-forward AFTER the image is built,
# so rollout is skipped and a "completed" pipeline ships nothing.
set -uo pipefail

ROOT=$(mktemp -d)
trap 'rm -rf "$ROOT"' EXIT

git init -q --bare "$ROOT/origin.git"
# GitHub refuses non-fast-forward pushes; a bare repo does not by default, so
# say so explicitly or the reproduction silently succeeds and proves nothing.
git -C "$ROOT/origin.git" config receive.denyNonFastForwards true
git init -q "$ROOT/seed"
cd "$ROOT/seed"
git config user.email t@t; git config user.name t
mkdir -p trust-page
echo "sha256:BASE" > trust-page/image-digest-gcp.txt
git add -A && git commit -qm base
git branch -M main
git remote add origin "$ROOT/origin.git"
git push -q origin main

# Run A: the deploy that gets there first.
git clone -q "$ROOT/origin.git" "$ROOT/runA"
cd "$ROOT/runA"
git config user.email t@t; git config user.name t
echo "sha256:AAA" > trust-page/image-digest-gcp.txt
git add -A && git commit -qm "[bot] enclave release A"
git push -q origin HEAD:main

# Run B: queued behind A, checked out BEFORE A pushed, so it is now stale.
git clone -q "$ROOT/origin.git" "$ROOT/runB"
cd "$ROOT/runB"
git config user.email t@t; git config user.name t
git reset -q --hard HEAD~1          # stale checkout: does not have A's commit
echo "sha256:BBB" > trust-page/image-digest-gcp.txt
git add -A && git commit -qm "[bot] enclave release B"

echo "--- OLD behaviour (plain push):"
out=$(git push origin HEAD:main 2>&1); echo "    $out" | tail -2
if echo "$out" | grep -q "rejected\|denied"; then
  echo "    REPRODUCED: push rejected, rollout would be skipped"
else
  echo "    FAILED TO REPRODUCE — the test proves nothing"; exit 1
fi

echo "--- NEW behaviour (rebase and retry):"
ok=0
for attempt in 1 2 3; do
  if git push -q origin HEAD:main 2>/dev/null; then ok=1; break; fi
  git fetch -q origin main
  if ! git rebase -q -X theirs origin/main 2>/dev/null; then
    git rebase --abort 2>/dev/null || true
    echo "    rebase failed"; exit 1
  fi
done
[ "$ok" = 1 ] || { echo "    push still failed"; exit 1; }
echo "    pushed after rebase"

# The artifacts must describe THIS run's image, not the one it rebased over.
cd "$ROOT/seed" && git fetch -q origin main && got=$(git show origin/main:trust-page/image-digest-gcp.txt)
if [ "$got" = "sha256:BBB" ]; then
  echo "    digest is BBB — the replayed commit won, as intended"
else
  echo "    WRONG: digest is $got; -X ours/theirs is inverted and we published the wrong image"
  exit 1
fi

# And A's commit must still be in history, not clobbered.
# Capture first: `set -o pipefail` plus `grep -q` reports the pipeline as
# FAILED even on a match, because grep exits early and git log takes SIGPIPE.
history=$(git log origin/main --oneline)
echo "    history: $(echo "$history" | tr '\n' ' ')"
if case "$history" in *"release A"*) true ;; *) false ;; esac; then
  echo "    run A's commit is still in history"
else
  echo "    WRONG: run A's release commit was discarded"; exit 1
fi

# Negative control: the strategy flag is inverted from intuition during a
# rebase, so prove that getting it wrong actually publishes the wrong image
# rather than being a harmless stylistic choice.
echo "--- negative control (-X ours, the intuitive-but-wrong flag):"
git clone -q "$ROOT/origin.git" "$ROOT/runC"
cd "$ROOT/runC"
git config user.email t@t; git config user.name t
git reset -q --hard HEAD~2                     # stale, before A and B
echo "sha256:CCC" > trust-page/image-digest-gcp.txt
git add -A && git commit -qm "[bot] enclave release C"
git fetch -q origin main
git rebase -q -X ours origin/main 2>/dev/null || { echo "    rebase failed"; exit 1; }
wrong=$(git show HEAD:trust-page/image-digest-gcp.txt)
if [ "$wrong" = "sha256:CCC" ]; then
  echo "    UNEXPECTED: -X ours also kept our digest; the flag choice is untested"
  exit 1
fi
echo "    -X ours yields $wrong, not CCC — the wrong image would be published"

echo "PASS"
