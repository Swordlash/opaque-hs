#!/bin/sh
# Build libsodium from source, as a static library: natively, for a machine
# whose own libsodium is too old, or for wasm32-wasi, for the package's flag
# wasm-libsodium.
#
#   sh scripts/libsodium.sh install [PREFIX]   # download, check, build, unless it is there
#   sh scripts/libsodium.sh ready [PREFIX]     # read-only: exit 0 when it is installed
#   sh scripts/libsodium.sh env [PREFIX]       # KEY=VALUE lines of the variables a build needs
#
#   sh scripts/libsodium.sh install-wasm [PREFIX]
#   sh scripts/libsodium.sh ready-wasm [PREFIX]
#   sh scripts/libsodium.sh env-wasm [PREFIX]  # the options cabal needs, on one line
#
# PREFIX is .libsodium in the repository by default, and .libsodium-wasm
# for the wasm modes. A PREFIX given must be a new or empty directory, or
# one this script filled before: it deletes what is in it.
#
# Natively. The package needs libsodium 1.0.19 or later for its
# HKDF-SHA-512, found through pkg-config. Debian 12 and Ubuntu 24.04 ship
# 1.0.18. A machine with a newer libsodium-dev needs none of this. On one
# without, either build with the flag older-libsodium, or run this script:
# it builds the release pinned below, checked against its checksum, and
# `env` prints the PKG_CONFIG_PATH that makes cabal find it. CI uses it.
#
# It is built without a shared library (--disable-shared), so a program
# linked with it carries libsodium inside and needs no libsodium package
# where it runs; --with-pic, because GHC links position-independent
# executables. The libsodium.pc installed here names the library
# libsodium-static, a link to libsodium.a: a name no system library has,
# so that the linker cannot take an older libsodium.so of the system's
# instead, whatever order its directories come in.
#
# For wasm32-wasi. libsodium publishes no build for it, so the same
# release is compiled with the wasi-sdk that comes with GHC's WebAssembly
# toolchain (ghc-wasm-meta, ~/.ghc-wasm): wasm32-wasi-clang, llvm-ar and
# llvm-ranlib must be on PATH, as they are after `. ~/.ghc-wasm/env`. It is
# compiled as position-independent code (-fPIC), since a wasm build that
# uses Template Haskell makes a shared object of every package, and this
# package's links libsodium in; without threads, a stack protector or a
# shared library, none of which wasm32-wasi has. cabal runs the host's
# pkg-config, which knows nothing of this library, so the package links
# `-lsodium` there and `env-wasm` prints the two options that say where it
# is: --extra-lib-dirs and --extra-include-dirs.
#
# The release comes from download.libsodium.org, or where that host is
# refused, from the same release on GitHub; both serve the same file, and
# the checksum is checked either way. Building needs a C compiler (the
# wasi-sdk's for wasm), make, curl, tar, gzip and sha256sum, and takes
# under a minute.
set -eu

# libsodium-<version>.tar.gz, the same file on download.libsodium.org and
# on the GitHub release <version>-RELEASE of jedisct1/libsodium.
LIBSODIUM_VERSION=1.0.22
LIBSODIUM_SHA256=adbdd8f16149e81ac6078a03aca6fc03b592b89ef7b5ed83841c086191be3349

mode=${1:-install}
root=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
# The target, and the mode without it.
case $mode in
  *-wasm)
    target=wasm
    mode=${mode%-wasm}
    prefix=${2:-$root/.libsodium-wasm}
    ;;
  *)
    target=native
    prefix=${2:-$root/.libsodium}
    ;;
esac
# A relative PREFIX is taken from the directory the script is run in. It
# is made absolute here: the build changes directory, and the pkg-config
# file and `env` must name a place that holds from anywhere.
case $prefix in
  /*) ;;
  *) prefix=$PWD/$prefix ;;
esac
mark="$LIBSODIUM_VERSION $LIBSODIUM_SHA256 $target"
owner=.opaque-hs-libsodium

say() { printf 'libsodium: %s\n' "$*"; }
die() {
  printf 'libsodium: %s\n' "$*" >&2
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

installed() {
  [ "$(cat "$prefix/.built" 2>/dev/null || true)" = "$mark" ] &&
    [ -f "$prefix/lib/libsodium.a" ] &&
    [ -f "$prefix/include/sodium.h" ] &&
    { [ "$target" = wasm ] || {
      [ -f "$prefix/lib/libsodium-static.a" ] && [ -f "$prefix/lib/pkgconfig/libsodium.pc" ]
    }; }
}

fetch() {
  curl --fail --location --retry 5 --silent --show-error --output "$2" "$1"
}

case $mode in
  ready)
    installed
    ;;
  env)
    if [ "$target" = wasm ]; then
      printf -- '--extra-lib-dirs=%s --extra-include-dirs=%s\n' "$prefix/lib" "$prefix/include"
    else
      printf 'PKG_CONFIG_PATH=%s\n' "$prefix/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}"
    fi
    ;;
  install)
    if installed; then
      say "libsodium $LIBSODIUM_VERSION is already in $prefix"
      exit 0
    fi
    compilers=cc
    [ "$target" = native ] || compilers="wasm32-wasi-clang llvm-ar llvm-ranlib"
    for tool in $compilers make curl tar gzip sha256sum; do
      command -v "$tool" >/dev/null 2>&1 ||
        die "$tool is needed and is not on PATH$([ "$target" = native ] || printf ' (run . ~/.ghc-wasm/env first)')"
    done
    say "building libsodium $LIBSODIUM_VERSION from source into $prefix$([ "$target" = native ] || printf ', for wasm32-wasi')"
    name=libsodium-$LIBSODIUM_VERSION.tar.gz
    claim
    # What an earlier, unfinished run left; nothing else is in a prefix
    # this script owns.
    rm -rf "$prefix/src" "$prefix/include" "$prefix/lib" "$prefix/.built" "$prefix/$name"
    mkdir -p "$prefix/src"
    archive=$prefix/$name
    if ! fetch "https://download.libsodium.org/libsodium/releases/$name" "$archive"; then
      say "download.libsodium.org did not give $name; fetching the same release from GitHub"
      fetch "https://github.com/jedisct1/libsodium/releases/download/$LIBSODIUM_VERSION-RELEASE/$name" "$archive" ||
        die "downloading $name failed"
    fi
    printf '%s  %s\n' "$LIBSODIUM_SHA256" "$archive" | sha256sum --check --status ||
      die "$name does not have the pinned checksum; nothing was built"
    tar xzf "$archive" --strip-components=1 --directory "$prefix/src"
    jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf 2)
    if [ "$target" = native ]; then
      # The archive's own compiler flags stand; only the kind of library
      # is chosen. A cross compiler's CC in the environment (~/.ghc-wasm/env
      # exports one) must not reach a native library.
      (
        cd "$prefix/src"
        unset CC CFLAGS LDFLAGS AR RANLIB
        ./configure --prefix="$prefix" --disable-shared --enable-static --with-pic --disable-dependency-tracking >/dev/null
        make -j"$jobs" >/dev/null
        make install >/dev/null
      )
      ln -s libsodium.a "$prefix/lib/libsodium-static.a"
      pc=$prefix/lib/pkgconfig/libsodium.pc
      # shellcheck disable=SC2016 # ${libdir} is the .pc file's own variable.
      sed -e 's|^Libs: .*|Libs: -L${libdir} -lsodium-static|' "$pc" >"$pc.tmp"
      mv "$pc.tmp" "$pc"
    else
      # The wasi-sdk's compiler and archiver, named here whatever CC the
      # environment has.
      (
        cd "$prefix/src"
        unset LDFLAGS
        CC=wasm32-wasi-clang AR=llvm-ar RANLIB=llvm-ranlib CFLAGS='-O2 -fPIC' \
          ./configure --host=wasm32-wasi --prefix="$prefix" --disable-pie --disable-ssp --disable-shared \
          --without-pthreads --disable-dependency-tracking >/dev/null
        make -j"$jobs" >/dev/null
        make install >/dev/null
      )
    fi
    rm -rf "$prefix/src" "$archive"
    printf '%s\n' "$mark" >"$prefix/.built"
    installed || die "the install in $prefix is incomplete after make install"
    if [ "$target" = native ]; then
      say "built; for cabal: export PKG_CONFIG_PATH=$prefix/lib/pkgconfig:\$PKG_CONFIG_PATH"
    else
      say "built; for cabal: --extra-lib-dirs=$prefix/lib --extra-include-dirs=$prefix/include"
    fi
    ;;
  *)
    die "unknown mode $mode (install, ready or env, or each with -wasm)"
    ;;
esac
