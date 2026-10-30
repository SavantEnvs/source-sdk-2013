#!/usr/bin/env bash
#
# mayhem/build.sh — builds the Source SDK 2013 fuzz targets (tier1 library code + vendored libspng) and the
# functional test program. Runs inside the commit image as `mayhem` in /mayhem; fully offline.
#
# The SDK is normally built by VPC + GCC. Here the tier1 library is compiled directly from source with clang
# (defines/includes taken from vpc_scripts/source_posix_base.vpc). Valve's prebuilt 64-bit libtier0.so and
# libvstdlib.so (src/lib/public/linux64) are linked at runtime through an rpath.
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
: "${COVERAGE_FLAGS=}"
: "${SRC:=/mayhem}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"
OUT="$SRC/mayhem/build"
LIBDIR="$SRC/src/lib/public/linux64"
SPNG="$SRC/src/thirdparty/libspng"
rm -rf "$OUT"
mkdir -p "$OUT/san" "$OUT/plain"

DEFS="-DGNUC -DPOSIX -D_POSIX -DCOMPILER_GCC -D_DLL_EXT=.so -D_LINUX -DLINUX -DPLATFORM_64BITS -DSOURCESDK -DNDEBUG -DTIER1_STATIC_LIB -DVPC"
INC="-I$SRC/src/common -I$SRC/src/public -I$SRC/src/public/tier0 -I$SRC/src/public/tier1"
SHIM="-include $SRC/mayhem/compat/clang_compat.h"
CXXSTD="-std=gnu++14 -w -fpermissive -fno-strict-aliasing"
LINKLIBS="-L$LIBDIR -ltier0 -lvstdlib -Wl,-rpath,$LIBDIR -lz -lm"

# tier1 files that are not part of the fuzzed library surface or do not build with clang on Linux:
#   fileio (typedef clash with the system headers), undiff (duplicates ApplyDiffs from diff),
#   lzmaDecoder (needs the prebuilt lzma .a), pathmatch (Windows-only)
SKIP=" fileio undiff lzmaDecoder pathmatch "
# snappy*.cpp conflict with the shim (ambiguous min).
NOSHIM=" snappy snappy-sinksource snappy-stubs-internal "

# Narrow, per-file UBSan relaxations for benign patterns (everything else, and all of ASan, stays halting):
#   alignment: the SDK's packed byte buffers store ints at unaligned offsets (utlbuffer.h, bitbuf.h) - fine on x86
#   bitbuf: 32-bit shifts by 32 and signed shift/overflow in the bit-twiddling reader (result masked afterwards)
#   KeyValues: enum loaded from an unvalidated type byte that is range-checked right after
#   strtools/KeyValues: integer parsing (V_atoi64, hex UINT64 keys) wraps on overlong digit strings
#   spng: float->uint cast of out-of-range cHRM values, rejected right after by check_chrm_int
relax_for() {
  [ -n "${SANITIZER_FLAGS}" ] || return 0
  case "$1" in
    bitbuf|fuzz_bitbuf) echo "-fno-sanitize=alignment,shift,signed-integer-overflow";;
    KeyValues) echo "-fno-sanitize=alignment,enum,signed-integer-overflow";;
    strtools) echo "-fno-sanitize=alignment,signed-integer-overflow";;
    spng) echo "-fno-sanitize=float-cast-overflow";;
    *) echo "-fno-sanitize=alignment";;
  esac
}

build_tier1() { # <objdir> <flags...>
  local dir="$1"; shift
  local cmds="$OUT/$(basename "$dir").cmds"
  : > "$cmds"
  for f in "$SRC"/src/tier1/*.cpp; do
    local b; b=$(basename "$f" .cpp)
    case "$SKIP" in *" $b "*) continue;; esac
    local extra="$SHIM"
    case "$NOSHIM" in *" $b "*) extra="";; esac
    [ "$dir" = "$OUT/san" ] && extra="$extra $(relax_for "$b")"
    echo "$CXX $CXXSTD $* $DEFS $INC $extra -c $f -o $dir/$b.o" >> "$cmds"
  done
  xargs -P "$MAYHEM_JOBS" -I{} bash -c '{}' < "$cmds"
  $CC "$@" $DEFS $([ "$dir" = "$OUT/san" ] && relax_for spng) -I"$SRC/mayhem/compat/inc" -c "$SPNG/spng/spng.c" -o "$dir/spng.o"
}

# --- sanitized build of the project, used by every fuzz target ---
# fuzzer-no-link adds libFuzzer coverage instrumentation to the project objects (not just the harness)
SAN="$SANITIZER_FLAGS $DEBUG_FLAGS -fsanitize=fuzzer-no-link"
build_tier1 "$OUT/san" $SAN
$CXX $SAN -c "$SRC/mayhem/lsan_off.cc" -o "$OUT/san/lsan_off.o"
$CC $SAN -c "$STANDALONE_FUZZ_MAIN" -o "$OUT/san/standalone_main.o"
TIER1_SAN=$(ls "$OUT"/san/*.o | grep -v -e standalone_main -e lsan_off -e '/spng\.o$')

harness() { # <name> <source> <lang: c|cc> <objs...>
  local name="$1" src="$2" lang="$3"; shift 3
  local objs="$*"
  local cflags="$SAN $DEFS $INC $(relax_for "$name")"
  local comp="$CXX $CXXSTD $SHIM"
  [ "$lang" = c ] && comp="$CC"
  [ "$name" = fuzz_snappy ] && comp="$CXX $CXXSTD"
  $comp $cflags -c "$src" -o "$OUT/san/h_$name.o"
  $CXX $SAN $LIB_FUZZING_ENGINE "$OUT/san/h_$name.o" $objs "$OUT/san/lsan_off.o" $LINKLIBS -o "$SRC/$name"
  $CXX $SAN "$OUT/san/h_$name.o" "$OUT/san/standalone_main.o" $objs "$OUT/san/lsan_off.o" $LINKLIBS -o "$SRC/$name-standalone"
}

for h in fuzz_keyvalues fuzz_keyvaluesjson fuzz_lzss fuzz_snappy fuzz_bitbuf; do
  harness "$h" "$SRC/mayhem/harnesses/$h.cc" cc $TIER1_SAN
done
harness spng_read_fuzzer "$SPNG/tests/spng_read_fuzzer.c" c "$OUT/san/spng.o"
harness spng_write_fuzzer "$SPNG/tests/spng_write_fuzzer.c" c "$OUT/san/spng.o"

# --- test program, project's normal flags, no sanitizers ---
PLAIN="-O1 $COVERAGE_FLAGS"
build_tier1 "$OUT/plain" $PLAIN
TIER1_PLAIN=$(ls "$OUT"/plain/*.o | grep -v '/spng\.o$')
$CXX $CXXSTD $PLAIN $DEFS $INC -I"$SPNG" -include "$SRC/mayhem/compat/clang_compat.h" \
  -c "$SRC/mayhem/tests/sdk_tests.cc" -o "$OUT/plain/sdk_tests.o"
$CXX $PLAIN "$OUT/plain/sdk_tests.o" $TIER1_PLAIN "$OUT/plain/spng.o" $LINKLIBS -o "$OUT/sdk_tests"
