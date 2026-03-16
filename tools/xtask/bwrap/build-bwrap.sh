#!/bin/sh
set -eu

: "${BWRAP_SRC:?BWRAP_SRC is required}"
: "${OUT_DIR:?OUT_DIR is required}"

if [ ! -d "${BWRAP_SRC}" ]; then
  echo "bubblewrap source directory does not exist: ${BWRAP_SRC}" >&2
  exit 1
fi

if command -v musl-gcc >/dev/null 2>&1; then
  export CC="musl-gcc"
elif command -v x86_64-linux-musl-gcc >/dev/null 2>&1; then
  export CC="x86_64-linux-musl-gcc"
elif command -v gcc >/dev/null 2>&1; then
  export CC="gcc"
else
  echo "no supported C compiler found for static bwrap build" >&2
  exit 3
fi

BUILD_ROOT="$(mktemp -d /tmp/bwrap-build.XXXXXX)"
cleanup() {
  rm -rf "${BUILD_ROOT}"
}
trap cleanup EXIT INT TERM

cp -a "${BWRAP_SRC}" "${BUILD_ROOT}/src"
cd "${BUILD_ROOT}/src"

export CFLAGS="${CFLAGS:--O2}"
export LDFLAGS="${LDFLAGS:--static}"
export PKG_CONFIG_ALL_STATIC="${PKG_CONFIG_ALL_STATIC:-1}"
export PKG_CONFIG_ALLOW_SYSTEM_CFLAGS="${PKG_CONFIG_ALLOW_SYSTEM_CFLAGS:-1}"
export PKG_CONFIG_ALLOW_SYSTEM_LIBS="${PKG_CONFIG_ALLOW_SYSTEM_LIBS:-1}"

echo "using CC=${CC}"
meson setup build \
  --buildtype=release \
  -Ddefault_library=static \
  -Dprefer_static=true \
  -Dtests=false \
  -Dman=disabled \
  -Dselinux=disabled
ninja -C build bwrap

mkdir -p "${OUT_DIR}"
cp build/bwrap "${OUT_DIR}/bwrap"
chmod 0755 "${OUT_DIR}/bwrap"

if command -v strip >/dev/null 2>&1; then
  strip "${OUT_DIR}/bwrap" || true
fi

file "${OUT_DIR}/bwrap"
ldd "${OUT_DIR}/bwrap" || true
