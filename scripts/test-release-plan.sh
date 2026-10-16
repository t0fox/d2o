#!/bin/sh
# scripts/release-plan.sh decides from git history alone, so a throwaway
# repository is enough to test it. No network, no GitHub.
set -eu
ROOT=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
PLAN="$ROOT/scripts/release-plan.sh"
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT
fails=0

g() { git -C "$T/repo" "$@"; }
commit() { g commit -q --allow-empty -m "$1"; }
# run [ENV=VALUE ...]: plan the repository, keep its output in $T/out
run() {
    rm -f "$T/out"
    ( cd "$T/repo" && env GITHUB_OUTPUT="$T/out" NOW=20261013-0102 "$@" sh "$PLAN" >/dev/null )
}
key() { sed -n "s/^$1=//p" "$T/out"; }
notes() { sed -n '/^notes<</,/^D2O_NOTES_EOF$/p' "$T/out" | sed '1d;$d'; }
expect() {
    if [ "$2" = "$3" ]; then echo "ok: $1"
    else echo "FAIL: $1: expected '$3', got '$2'" >&2; fails=$((fails + 1)); fi
}
has() {
    if notes | grep -qxF -- "$2"; then echo "ok: $1"
    else echo "FAIL: $1: notes lack '$2'" >&2; notes >&2; fails=$((fails + 1)); fi
}
lacks() {
    if notes | grep -qF -- "$2"; then echo "FAIL: $1: notes hold '$2'" >&2; fails=$((fails + 1))
    else echo "ok: $1"; fi
}

mkdir "$T/repo"
g init -q
g config user.email test@example.invalid
g config user.name test
g config commit.gpgsign false
g config tag.gpgsign false

commit "init"
run
expect "no release without a fix or a feature" "$(key release)" false

g tag d2o-20261012-2144-aaaaaaa
commit "ci: speed"
commit "test(sched): hermetic"
commit "docs(readme): rewrite"
commit "build: refresh builds/"
commit "refactor(quic): delete the arm picker"
run
expect "ci, test, docs, build, refactor alone make no release" "$(key release)" false

commit "fixup: not a fix"
commit "prefix: not a fix either"
run
expect "a type that only starts with fix is not fix" "$(key release)" false

commit "fix(S99d2k): five A&&B||C rewritten as real ifs"
run
short=$(g rev-parse --short=7 HEAD)
expect "a fix since the last release makes one" "$(key release)" true
expect "the id carries the time and the commit" "$(key id)" "d2o-20261013-0102-$short"
expect "the version carries the date and the commit" "$(key version)" "13.10.2026 ($short)"
expect "the release is the exact commit planned" "$(key sha)" "$(g rev-parse HEAD)"
has "the fix is in the notes" "- fix(S99d2k): five A&&B||C rewritten as real ifs"
lacks "ci is not in the notes" "ci: speed"
lacks "refactor is not in the notes" "refactor(quic)"

commit "feat(panel): clear what was found"
commit "perf: faster probe"
commit "docs+fix: README and a missing test"
commit "refactor(core)!: change the plan format"
run
has "feat is in the notes" "- feat(panel): clear what was found"
has "perf is in the notes" "- perf: faster probe"
has "a combined type with fix counts" "- docs+fix: README and a missing test"
has "a breaking change of any type counts" "- refactor(core)!: change the plan format"

g tag d2o-20261013-0000-bbbbbbb
commit "test: more"
g commit -q --allow-empty -m "chore: drop the old flag" -m "BREAKING CHANGE: the flag is gone"
run
expect "a BREAKING CHANGE footer makes a release" "$(key release)" true
lacks "notes start after the last release" "feat(panel)"

g tag d2o-20261013-0100-ccccccc
run FORCE=1
expect "a released commit is never released again, even by hand" "$(key release)" false

commit "ci: only ci"
run FORCE=1
expect "a manual run releases without a fix" "$(key release)" true
has "a manual run without notes says what it is" "Выпуск d2o 13.10.2026 ($(g rev-parse --short=7 HEAD))"

run FORCE=1 NOTES="Две строки
для людей"
has "notes given by hand replace the list" "для людей"

if [ "$fails" -ne 0 ]; then
    echo "test-release-plan: $fails failed" >&2
    exit 1
fi
echo "test-release-plan: all passed"
