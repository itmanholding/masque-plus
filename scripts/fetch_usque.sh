#!/usr/bin/env bash
set -euo pipefail

if ! command -v yq >/dev/null 2>&1; then
  echo "yq is required"
  exit 1
fi
if ! command -v gh >/dev/null 2>&1; then
  echo "gh is required"
  exit 1
fi

VERSION="$(yq -r '.version' usque.yaml)"
TARGET_OS="${1:?TARGET_OS missing}"
TARGET_ARCH="${2:?TARGET_ARCH missing}"

ASSET_BASE="usque_${VERSION}_${TARGET_OS}_${TARGET_ARCH}"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
pushd "$WORKDIR" >/dev/null

ASSET_NAME="$(gh release view "v${VERSION}" --repo Diniboy1123/usque --json assets -q ".assets[].name" | grep -E "^${ASSET_BASE}\.(zip|tar\.gz)$" | head -n1 || true)"
if [ -z "${ASSET_NAME}" ]; then
  echo "no matching asset for ${ASSET_BASE}"
  exit 1
fi

gh release download "v${VERSION}" --repo Diniboy1123/usque -p "${ASSET_NAME}"

mkdir extracted
if [[ "${ASSET_NAME}" == *.zip ]]; then
  unzip -q "${ASSET_NAME}" -d extracted
else
  tar -xzf "${ASSET_NAME}" -C extracted
fi

rm -f extracted/README.md extracted/License.md extracted/LICENSE.md extracted/readme.md || true

if [ "${TARGET_OS}" = "windows" ]; then
  BIN="$(find extracted -maxdepth 1 -type f -name 'usque*.exe' | head -n1 || true)"
else
  BIN="$(find extracted -maxdepth 1 -type f -name 'usque*' ! -name '*.md' ! -name '*.txt' | head -n1 || true)"
fi
if [ -z "$BIN" ]; then
  echo "binary not found"
  exit 1
fi

popd >/dev/null

OUT_DIR="build/vendor/usque/${TARGET_OS}_${TARGET_ARCH}"
mkdir -p "$OUT_DIR"
cp "$WORKDIR/$BIN" "$OUT_DIR/"
if [ "$TARGET_OS" != "windows" ]; then
  chmod +x "$OUT_DIR/$(basename "$BIN")"
fi

echo "Prepared: $OUT_DIR/$(basename "$BIN")"
