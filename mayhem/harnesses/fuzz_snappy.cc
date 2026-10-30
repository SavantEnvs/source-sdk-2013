// Google snappy as vendored in tier1/snappy*.cpp: decompress arbitrary streams, round-trip arbitrary data.
#include "tier1/snappy.h"
#include <stdint.h>
#include <stddef.h>
#include <string>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 1) return -1;
  const char *in = (const char *)data;
  size_t ulen = 0;
  bool have_len = snappy::GetUncompressedLength(in, size, &ulen);
  bool valid = snappy::IsValidCompressedBuffer(in, size);
  if (have_len && valid && ulen <= (1u << 22)) {
    std::string out;
    if (!snappy::Uncompress(in, size, &out)) __builtin_trap();
    if (out.size() != ulen) __builtin_trap();
  }
  if (size <= (1u << 16)) {
    std::string comp, back;
    snappy::Compress(in, size, &comp);
    if (!snappy::Uncompress(comp.data(), comp.size(), &back)) __builtin_trap();
    if (back.size() != size || back.compare(0, size, in, size) != 0) __builtin_trap();
  }
  return valid ? 0 : -1;
}
