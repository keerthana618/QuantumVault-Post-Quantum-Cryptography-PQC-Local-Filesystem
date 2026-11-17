#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LIBOQS_DIR="${LIBOQS_DIR:-${ROOT_DIR}/.vendor/liboqs}"

pick_tool() {
  local preferred="${1}"
  if [ -n "${preferred}" ] && [ -x "${preferred}" ]; then
    printf '%s\n' "${preferred}"
    return 0
  fi
  if command -v "${2}" >/dev/null 2>&1; then
    command -v "${2}"
    return 0
  fi
  return 1
}

CMAKE_BIN="${CMAKE_BIN:-}"
NINJA_BIN="${NINJA_BIN:-}"

if [ -z "${CMAKE_BIN}" ]; then
  CMAKE_BIN="$(pick_tool "${CMAKE_BIN}" cmake || true)"
fi
if [ -z "${NINJA_BIN}" ]; then
  NINJA_BIN="$(pick_tool "${NINJA_BIN}" ninja || true)"
fi

if [ -z "${CMAKE_BIN}" ]; then
  for candidate in \
    "/c/Program Files/CMake/bin/cmake.exe" \
    "/c/Program Files/CMake/bin/cmake" \
    "/c/Users/Asus/AppData/Local/Python/pythoncore-3.14-64/Scripts/cmake.exe" \
    "/usr/bin/cmake"; do
    if [ -x "${candidate}" ] || [ -f "${candidate}" ]; then
      CMAKE_BIN="${candidate}"
      break
    fi
  done
fi

if [ -z "${NINJA_BIN}" ]; then
  for candidate in \
    "/c/Android/Sdk/cmake/3.22.1/bin/ninja.exe" \
    "/c/Android/Sdk/cmake/3.22.1/bin/ninja" \
    "/c/Users/Asus/AppData/Local/Python/pythoncore-3.14-64/Scripts/ninja.exe" \
    "/usr/bin/ninja"; do
    if [ -x "${candidate}" ] || [ -f "${candidate}" ]; then
      NINJA_BIN="${candidate}"
      break
    fi
  done
fi

if [ -z "${CMAKE_BIN}" ]; then
  echo "cmake is required to build liboqs. Install the build dependencies first." >&2
  exit 127
fi

if [ -z "${NINJA_BIN}" ]; then
  echo "ninja is required to build liboqs. Install the build dependencies first." >&2
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
CMAKE_ARGS=( -S . -B build -G Ninja -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=OFF )
if [ -n "${CC:-}" ]; then
  CMAKE_ARGS+=( -DCMAKE_C_COMPILER="${CC}" )
fi
if [ -n "${CXX:-}" ]; then
  CMAKE_ARGS+=( -DCMAKE_CXX_COMPILER="${CXX}" )
fi
if [ -n "${CMAKE_MAKE_PROGRAM:-}" ]; then
  CMAKE_ARGS+=( -DCMAKE_MAKE_PROGRAM="${CMAKE_MAKE_PROGRAM}" )
else
  CMAKE_ARGS+=( -DCMAKE_MAKE_PROGRAM="${NINJA_BIN}" )
fi

"${CMAKE_BIN}" "${CMAKE_ARGS[@]}"
"${CMAKE_BIN}" --build build --parallel
ctest --test-dir build --output-on-failure -R KEM

echo "liboqs build finished and the KEM checks completed successfully."
