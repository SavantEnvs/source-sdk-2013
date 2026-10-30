// Valve LZSS: bounded decoder over attacker-controlled streams, plus a compress/decompress round-trip.
#include "tier1/lzss.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < sizeof(lzss_header_t)) return -1;
  CLZSS lzss;
  if (CLZSS::IsCompressed(data)) {
    unsigned int actual = CLZSS::GetActualSize(data);
    if (actual > (1u << 22)) return -1;
    unsigned char *out = (unsigned char *)malloc(actual ? actual : 1);
    lzss.SafeUncompress(data, (unsigned int)size, out, actual);
    free(out);
  }
  if (size <= (1u << 16)) {
    unsigned int csize = 0;
    unsigned char *comp = lzss.Compress(data, (int)size, &csize);
    if (comp) {
      unsigned char *back = (unsigned char *)malloc(size);
      unsigned int n = lzss.Uncompress(comp, back);
      if (n != size || memcmp(back, data, size) != 0) __builtin_trap();
      free(back);
      free(comp);
    }
  }
  return 0;
}
