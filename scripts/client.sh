#!/bin/sh
# Run the client of GHC's WebAssembly or JavaScript backend
# (test-client/Main.hs, compiled) under Node.
#
#   sh scripts/client.sh wasm [serve]
#   sh scripts/client.sh js [serve]
#
# With no argument the program tests itself against serenity-kit's server.
# With serve it answers one command a line, for the native test suite:
#
#   OPAQUE_HS_CLIENT="sh scripts/client.sh wasm serve" cabal test opaque-test
#
# The program is built first, into the build directory this script looks
# in:
#
#   cabal --project-file=cabal-wasm-client.project --builddir=dist-newstyle/wasm-client build all
#   cabal --project-file=cabal-js-client.project --builddir=dist-newstyle/js-client build all
#
# Both need Node and the repository's node_modules (npm ci), for
# @serenity-kit/opaque. The WebAssembly program also needs
# wasm32-wasi-ghc on PATH (. ~/.ghc-wasm/env): its post-link.mjs writes the
# JavaScript half of the program, beside it.
set -eu

backend=${1:-}
[ $# -gt 0 ] && shift
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)

die() {
  printf 'client: %s\n' "$*" >&2
  exit 1
}

# The one file of this name the build directory holds.
built() {
  found=$(find "$root/dist-newstyle/$1" -path "$2" -type f 2>/dev/null | head -n 1)
  [ -n "$found" ] || die "no $3 under dist-newstyle/$1; build it first (see this script's head)"
  printf '%s\n' "$found"
}

command -v node >/dev/null 2>&1 || die "node is needed and is not on PATH"

case $backend in
  wasm)
    program=$(built wasm-client '*/opaque-client-test.wasm' opaque-client-test.wasm)
    jsffi=$program.jsffi.mjs
    if [ ! -f "$jsffi" ] || [ "$program" -nt "$jsffi" ]; then
      command -v wasm32-wasi-ghc >/dev/null 2>&1 ||
        die "wasm32-wasi-ghc is needed and is not on PATH (run . ~/.ghc-wasm/env first)"
      node "$(wasm32-wasi-ghc --print-libdir)/post-link.mjs" --input "$program" --output "$jsffi"
    fi
    # Node's WASI is marked experimental, and says so on every run.
    exec node --disable-warning=ExperimentalWarning "$root/interop/client-wasm.mjs" "$program" "$jsffi" "$@"
    ;;
  js)
    program=$(built js-client '*/opaque-client-test.jsexe/all.js' opaque-client-test.jsexe/all.js)
    exec node "$program" "$@"
    ;;
  *)
    die "usage: sh scripts/client.sh wasm|js [serve]"
    ;;
esac
