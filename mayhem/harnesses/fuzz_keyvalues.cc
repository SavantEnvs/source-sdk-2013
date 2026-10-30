// KeyValues text (with and without escape sequences) and binary parsers, plus save round-trips.
#include "tier1/KeyValues.h"
#include "tier1/utlbuffer.h"
#include "kv_setup.h"
#include <stdint.h>
#include <stddef.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 2) return -1;
  const uint8_t mode = data[0];
  data++;
  size--;
  KeyValues *kv = new KeyValues("fuzz");
  if (mode & 1) {
    CUtlBuffer buf(data, (int)size, CUtlBuffer::READ_ONLY | CUtlBuffer::TEXT_BUFFER);
    kv->UsesEscapeSequences((mode & 2) != 0);
    if (kv->LoadFromBuffer("fuzz", buf)) {
      CUtlBuffer out(0, 0, CUtlBuffer::TEXT_BUFFER);
      kv->RecursiveSaveToFile(out, 0, (mode & 4) != 0, true);
      for (KeyValues *sub = kv->GetFirstSubKey(); sub; sub = sub->GetNextKey()) {
        sub->GetName();
        sub->GetString();
        sub->GetInt();
        sub->GetFloat();
      }
    }
  } else {
    CUtlBuffer buf(data, (int)size, CUtlBuffer::READ_ONLY);
    if (kv->ReadAsBinary(buf)) {
      CUtlBuffer out;
      kv->WriteAsBinary(out);
    }
  }
  kv->deleteThis();
  return 0;
}
