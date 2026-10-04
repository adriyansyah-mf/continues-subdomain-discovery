#!/usr/bin/env sh
# Clone the nuclei-templates repo at a pinned tag and verify the checkout against
# a pinned commit SHA (the release archives are not attached to the GitHub
# releases, and tag->commit is content-verifiable where tarball bytes are not).
# Used by the scanner image build (workers/common/Dockerfile).
# Usage: install-nuclei-templates.sh <outdir> <version> <commit-sha>
set -eu

OUT="$1"; VERSION="${2#v}"; COMMIT="$3"
[ -n "$OUT" ] && [ -n "$VERSION" ] && [ -n "$COMMIT" ] || { echo "usage: $0 <outdir> <version> <commit-sha>" >&2; exit 1; }
[ -n "$(command -v git)" ] || { echo "git not installed" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

echo "installing nuclei-templates v${VERSION} @ ${COMMIT}"
git clone --quiet --depth 1 --branch "v${VERSION}" --config advice.detachedHead=false \
  https://github.com/projectdiscovery/nuclei-templates.git "$WORK/tpl"
actual="$(git -C "$WORK/tpl" rev-parse HEAD)"
[ "$actual" = "$COMMIT" ] || { echo "commit mismatch: $actual != $COMMIT" >&2; exit 1; }
count="$(find "$WORK/tpl" -name '*.yaml' | wc -l)"
[ "$count" -gt 1000 ] || { echo "suspiciously few templates ($count)" >&2; exit 1; }
mkdir -p "$OUT"
mv "$WORK/tpl" "$OUT/nuclei-templates"
echo "v${VERSION}" > "$OUT/nuclei-templates-release"
echo "installed $count templates"
