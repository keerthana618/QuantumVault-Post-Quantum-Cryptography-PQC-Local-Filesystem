#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBOQS_DIR="${LIBOQS_DIR:-${ROOT_DIR}/.vendor/liboqs}"

if ! command -v cmake >/dev/null 2>&1; then
  echo "cmake is required to build liboqs. Install the build dependencies first." >&2
  exit 127
fi

if ! command -v git >/dev/null 2>&1; then
  echo "git is required to fetch liboqs." >&2
  exit 127
fi

if [ ! -d "${LIBOQS_DIR}/.git" ]; then
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git "${LIBOQS_DIR}"
fi

cd "${LIBOQS_DIR}"
cmake -S . -B build -GNinja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=OFF
cmake --build build --parallel
ctest --test-dir build --output-on-failure -R KEM

echo "liboqs build finished and the KEM checks completed successfully."
