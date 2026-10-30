// JSON -> KeyValues parser (tier1/keyvaluesjson.cpp).
#include "tier1/keyvaluesjson.h"
#include "tier1/KeyValues.h"
#include "tier1/utlbuffer.h"
#include "kv_setup.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  // The tokenizer peeks one byte past the end on a trailing '/', so (like a loaded text file) the input is NUL-terminated.
  char *text = (char *)malloc(size + 1);
  memcpy(text, data, size);
  text[size] = '\0';
  KeyValuesJSONParser parser(text, (int)size);
  KeyValues *kv = parser.ParseFile();
  if (!kv) { free(text); return -1; }
  CUtlBuffer out(0, 0, CUtlBuffer::TEXT_BUFFER);
  kv->RecursiveSaveToFile(out, 0);
  kv->deleteThis();
  free(text);
  return 0;
}
