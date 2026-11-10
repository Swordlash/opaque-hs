#!/bin/sh
# Build the reference implementation the tests compare this package with:
# libopaque and the liboprf it is written over, from source, as one static
# library.
#
#   sh scripts/reference.sh install [PREFIX]   # fetch, check, build, unless it is there
#   sh scripts/reference.sh ready [PREFIX]     # read-only: exit 0 when it is installed
#   sh scripts/reference.sh env [PREFIX]       # the PKG_CONFIG_PATH line a build needs
#
# PREFIX is .reference in the repository by default.
# A PREFIX given must be a new or empty directory, or one this script
# filled before: it deletes what is in it.
#
# libopaque (https://github.com/stef/libopaque) is an independent
# implementation of OPAQUE in C, over libsodium. The test suite
# opaque-reference (flag `reference` of opaque-hs.cabal) runs every step of
# a registration and a login through both and compares the bytes. Both
# libraries are under the LGPL, version 3 or later. Nothing of them is in
# this repository or in the package: this script fetches them, and they are
# linked into that one test program only, which is not distributed.
#
# The two commits below are pinned together: libopaque calls liboprf by the
# names it has at that commit. A fetched checkout that is not the pinned
# commit stops the script. With these commits liboprf's and libopaque's own
# programs reproduce the test vectors of RFC 9497 (appendix A.1.1) and of
# RFC 9807 (appendix C.1.1), checked when they were pinned.
#
# Only the files OPAQUE needs are compiled, with this script's own flags
# rather than the libraries' makefiles: those build shared libraries and
# link `-lsodium`, and the test program must hold exactly one libsodium,
# the one the package itself links (found through pkg-config, as cabal
# finds it). So the result is libopaque-reference.a and a pkg-config file,
# opaque-reference.pc, that requires `libsodium`. libopaque's and liboprf's
# sources both define a function `dump`; libopaque's is renamed so that the
# two can be in one archive.
#
# The two libraries take their random values from two functions of
# libsodium, `randombytes` and `crypto_core_ristretto255_scalar_random`.
# They are compiled with those two names replaced by
# `opaque_reference_randombytes` and `opaque_reference_scalar_random`,
# which the test suite defines (test-reference/cbits/shim.c): there they
# give libsodium's values, or the values a test wants a step to draw, so
# that a test can run both implementations on the same random values. So
# the archive links only together with that file.
#
# It needs git, a C compiler, ar, pkg-config and libsodium 1.0.19 or later
# (for its HKDF, as the package does without the flag older-libsodium).
set -eu

LIBOPRF_URL=https://github.com/stef/liboprf
LIBOPRF_COMMIT=f925b87759d06ac97abc5b926fe0e7d0668a05ce
LIBOPAQUE_URL=https://github.com/stef/libopaque
LIBOPAQUE_COMMIT=6e9ac92f9a2289679e04b0b0c5fdc307bb3de54e

mode=${1:-install}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
prefix=${2:-$root/.reference}
stamp="liboprf $LIBOPRF_COMMIT libopaque $LIBOPAQUE_COMMIT build 2"
owner=.opaque-hs-reference

say() { printf 'reference: %s\n' "$*"; }
die() {
  printf 'reference: %s\n' "$*" >&2
  exit 1
}

# The prefix is this script's own to delete and fill: a directory that does
# not exist yet, an empty one, or one this script made before (it leaves
# the file $owner in it). Anything else is refused untouched, so that a
# prefix such as ~/.local is never emptied.
claim() {
  if [ -e "$prefix" ] && [ ! -d "$prefix" ]; then
    die "$prefix is not a directory"
  fi
  if [ -d "$prefix" ] && [ ! -f "$prefix/$owner" ] && [ -n "$(ls -A "$prefix")" ]; then
    die "$prefix has files this script did not put there; give it a new or empty directory"
  fi
  mkdir -p "$prefix"
  : >"$prefix/$owner"
}

installed() { [ -f "$prefix/.built" ] && [ "$(cat "$prefix/.built")" = "$stamp" ]; }

# A checkout of one commit of a repository, in a directory of its own.
fetch() {
  url=$1 commit=$2 dir=$3
  rm -rf "$dir"
  mkdir -p "$dir"
  git -C "$dir" init -q
  git -C "$dir" fetch -q --depth 1 "$url" "$commit"
  git -C "$dir" checkout -q FETCH_HEAD
  found=$(git -C "$dir" rev-parse HEAD)
  [ "$found" = "$commit" ] || die "$url gave $found, not the pinned $commit"
}

case $mode in
  ready)
    installed
    ;;
  env)
    printf 'PKG_CONFIG_PATH=%s\n' "$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    ;;
  install)
    if installed; then
      say "already built in $prefix"
      exit 0
    fi
    for tool in git "${CC:-cc}" ar pkg-config; do
      command -v "$tool" >/dev/null 2>&1 || die "$tool is needed and is not on PATH"
    done
    pkg-config --atleast-version=1.0.19 libsodium ||
      die "libsodium 1.0.19 or later is needed, found through pkg-config (see the README)"
    sodium_cflags=$(pkg-config --cflags libsodium)

    claim
    rm -f "$prefix/.built"
    say "fetching liboprf $LIBOPRF_COMMIT"
    fetch "$LIBOPRF_URL" "$LIBOPRF_COMMIT" "$prefix/src/liboprf"
    say "fetching libopaque $LIBOPAQUE_COMMIT"
    fetch "$LIBOPAQUE_URL" "$LIBOPAQUE_COMMIT" "$prefix/src/libopaque"
    oprf=$prefix/src/liboprf/src
    opaque=$prefix/src/libopaque/src

    # The headers as an installed liboprf and libopaque have them:
    # opaque.h includes <oprf/toprf.h>.
    rm -rf "$prefix/include" "$prefix/lib" "$prefix/obj"
    mkdir -p "$prefix/include/oprf" "$prefix/lib/pkgconfig" "$prefix/obj"
    cp "$oprf"/*.h "$prefix/include/oprf/"
    cp "$opaque/opaque.h" "$prefix/include/"

    say "compiling"
    # HAVE_SODIUM_HKDF: libsodium has HKDF-SHA-512 itself from 1.0.19 on.
    # The two -D that rename libsodium's functions: see above.
    flags="-O2 -fPIC -std=gnu99 -Wno-attributes -DHAVE_SODIUM_HKDF=1"
    flags="$flags -Drandombytes=opaque_reference_randombytes"
    flags="$flags -Dcrypto_core_ristretto255_scalar_random=opaque_reference_scalar_random"
    flags="$flags -I$prefix/include -I$oprf -I$opaque $sodium_cflags"
    for source in oprf toprf utils; do
      # shellcheck disable=SC2086
      "${CC:-cc}" $flags -c -o "$prefix/obj/oprf_$source.o" "$oprf/$source.c"
    done
    for source in opaque common; do
      # shellcheck disable=SC2086
      "${CC:-cc}" $flags -Ddump=opaque_dump -c -o "$prefix/obj/opaque_$source.o" "$opaque/$source.c"
    done
    ar rcs "$prefix/lib/libopaque-reference.a" "$prefix"/obj/*.o

    cat >"$prefix/lib/pkgconfig/opaque-reference.pc" <<EOF
prefix=$prefix
libdir=\${prefix}/lib
includedir=\${prefix}/include

Name: opaque-reference
Description: libopaque and liboprf at pinned commits, for the tests of opaque-hs
Version: 0
Requires: libsodium >= 1.0.19
Libs: -L\${libdir} -lopaque-reference
Cflags: -I\${includedir}
EOF
    printf '%s\n' "$stamp" >"$prefix/.built"
    say "built in $prefix; for cabal: export PKG_CONFIG_PATH=$prefix/lib/pkgconfig:\$PKG_CONFIG_PATH"
    ;;
  *)
    die "unknown mode $mode (install, ready or env)"
    ;;
esac
