// Shared one-time setup for the KeyValues-based harnesses.
#pragma once
#include "tier0/dbg.h"
#include "tier1/KeyValues.h"
#include <stdio.h>

// Parse errors are reported through tier0 spew on stdout (hundreds of MB per run): drop messages and warnings,
// keep errors and asserts fatal.
static SpewRetval_t QuietSpew(SpewType_t type, const char *msg) {
  if (type == SPEW_ERROR || type == SPEW_ASSERT) {
    fputs(msg, stderr);
    return SPEW_ABORT;
  }
  return SPEW_CONTINUE;
}

// The default key-name table is a fixed pool shared by the whole process; a long fuzzing session exhausts it and
// the SDK then calls Error("Out of keyvalue string space"). Use the SDK's own growable table instead.
extern "C" int LLVMFuzzerInitialize(int *, char ***) {
  SpewOutputFunc(QuietSpew);
  KeyValues::SetUseGrowableStringTable(true);
  return 0;
}
