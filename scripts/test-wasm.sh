#!/usr/bin/env bash

set -eo pipefail
here="$(dirname "$0")"
src_root="$(readlink -f "${here}/..")"
cd "${src_root}"

(
  cd sdk-wasm-js
  npm install
  npm test
)

(
  cd sdk-wasm-js-tests
  npm install
  npm test
)

(
  cd system-wasm-js
  npm install
)
