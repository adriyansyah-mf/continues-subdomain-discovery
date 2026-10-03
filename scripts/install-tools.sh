#!/usr/bin/env sh
# Download pinned ProjectDiscovery release binaries and verify them against the
# release checksum file. Used by the scanner image build (workers/common/Dockerfile).
# Usage: install-tools.sh <outdir> tool=version [tool=version ...]
set -eu

OUT="$1"; shift
ARCH="${TARGETARCH:-amd64}"
mkdir -p "$OUT"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

for spec in "$@"; do
  tool="${spec%%=*}"
  version="${spec#*=}"
  version="${version#v}"
  [ -n "$tool" ] && [ -n "$version" ] || { echo "bad tool spec: $spec" >&2; exit 1; }
  base="https://github.com/projectdiscovery/${tool}/releases/download/v${version}"
  zip="${tool}_${version}_linux_${ARCH}.zip"
  echo "installing ${tool} v${version}"
  curl -fsSL --retry 3 -o "$WORK/$zip" "$base/$zip"
  # checksum file naming differs between projects (e.g. katana uses dashes)
  sums=""
  for name in "${tool}_${version}_checksums.txt" "${tool}-${version}-checksums.txt"; do
    if curl -fsSL --retry 3 -o "$WORK/sums.txt" "$base/$name"; then sums="$WORK/sums.txt"; break; fi
  done
  [ -n "$sums" ] || { echo "no checksum file for ${tool} v${version}" >&2; exit 1; }
  expected="$(grep " ${zip}\$" "$sums" | awk '{print $1}')"
  [ -n "$expected" ] || { echo "checksum for $zip not listed" >&2; exit 1; }
  echo "${expected}  $WORK/$zip" | sha256sum -c -
  unzip -o -q "$WORK/$zip" "$tool" -d "$OUT"
  chmod 0755 "$OUT/$tool"
done
