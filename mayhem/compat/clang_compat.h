// Force-included (-include) into every Source SDK translation unit built by mayhem/build.sh.
// Valve builds with GCC, which accepts V_swap() on bit-fields; clang rejects
// "non-const reference cannot bind to bit-field" inside CUtlBlockMemory::Swap. Parse that one header
// with a value-identical swap macro and restore the real template immediately, so upstream stays untouched.
#pragma once
#include "mathlib/mathlib.h"
#define V_swap(a, b) do { auto v_swap_tmp_ = (a); (a) = (b); (b) = v_swap_tmp_; } while (0)
#include "tier1/utlblockmemory.h"
#undef V_swap
