#!/bin/sh
# Decide whether HEAD is released, and with what notes. Called by
# .github/workflows/release.yml; tested by scripts/test-release-plan.sh.
#
# THE RULE is the one semantic-release and release-please use (Conventional
# Commits): a release goes out when at least one commit since the last release
# is a fix, a feature or a performance change, or breaks compatibility.
# ci:, test:, docs:, build:, refactor: alone change nothing a router sees, so
# they make no release by themselves; they go out with the next one.
#
# A manual run (FORCE=1) releases without such a commit. A commit that already
# has a release is never released again, also not by hand: a defect is fixed
# by the next release (RELEASING.md).
#
# Output: key=value lines (release, sha, id, version, notes) into
# $GITHUB_OUTPUT, or to stdout when it is not set.
#
#   [FORCE=1] [NOTES=...] [NOW=YYYYmmdd-HHMM] sh scripts/release-plan.sh
set -eu

FORCE=${FORCE:-0}
NOTES=${NOTES:-}
NOW=${NOW:-$(date -u +%Y%m%d-%H%M)}
OUTPUT=${GITHUB_OUTPUT:-/dev/stdout}

sha=$(git rev-parse HEAD)
short=$(git rev-parse --short=7 HEAD)
id="d2o-$NOW-$short"
day=${NOW%%-*}
version="$(echo "$day" | cut -c7-8).$(echo "$day" | cut -c5-6).$(echo "$day" | cut -c1-4) ($short)"

last=$(git describe --tags --abbrev=0 --match 'd2o-*' HEAD 2>/dev/null || true)
range=HEAD
[ -z "$last" ] || range="$last..HEAD"

# type(scope)!: subject. A combined type like docs+fix counts when one of its
# parts counts; "!" after the type marks a breaking change of any type.
worthy=$(git log --format=%s "$range" \
    | grep -E '^([a-z]+\+)*(feat|fix|perf)(\+[a-z]+)*(\([^)]*\))?!?: |^[a-z+]+(\([^)]*\))?!: ' || true)
breaking=$(git log --format=%s -E --grep='^BREAKING[ -]CHANGE: ' "$range")
if [ -n "$breaking" ]; then
    worthy=$(printf '%s\n%s\n' "$worthy" "$breaking" | grep -v '^$' | awk '!seen[$0]++')
fi

if [ -n "$last" ] && [ "$(git rev-parse "$last^{commit}")" = "$sha" ]; then
    release=false; why="$short already is release $last"
elif [ "$FORCE" = 1 ]; then
    release=true; why="manual run"
elif [ -n "$worthy" ]; then
    release=true; why="$(printf '%s\n' "$worthy" | wc -l | tr -d ' ') fix/feature commits since ${last:-the start}"
else
    release=false; why="no fix or feature since ${last:-the start}"
fi

if [ -n "$NOTES" ]; then
    notes=$NOTES
elif [ -n "$worthy" ]; then
    # The panel shows the notes; thirty lines is the most a person reads there.
    notes=$(printf 'Что изменилось:\n'; printf '%s\n' "$worthy" | head -n 30 | sed 's/^/- /')
else
    notes="Выпуск D2O $version"
fi

{
    echo "release=$release"
    echo "sha=$sha"
    echo "id=$id"
    echo "version=$version"
    echo "notes<<D2K_NOTES_EOF"
    printf '%s\n' "$notes"
    echo "D2K_NOTES_EOF"
} >> "$OUTPUT"
echo "release-plan: release=$release ($why)" >&2
