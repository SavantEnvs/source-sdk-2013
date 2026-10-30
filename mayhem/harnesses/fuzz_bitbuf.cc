// Network bit-stream reader (tier1/bitbuf.cpp). The leading bytes script a sequence of read operations
// over the remaining bytes, the way netmessages decode attacker-controlled packets.
#include "tier1/bitbuf.h"
#include "mathlib/vector.h"
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 8) return -1;
  const size_t nops = 16;
  const uint8_t *ops = data;
  data += nops < size ? nops : size;
  size -= nops < size ? nops : size;
  if (size == 0) return -1;
  // bf_read consumes whole 32-bit words: engine buffers are always a multiple of 4 bytes, so copy into a zero-padded one.
  size_t padded = (size + 3) & ~(size_t)3;
  uint8_t *copy = (uint8_t *)calloc(padded, 1);
  memcpy(copy, data, size);
  bf_read br(copy, (int)padded);
  char str[256];
  uint8_t bytes[64];
  for (size_t i = 0; i < nops; i++) {
    switch (ops[i] & 0x1f) {
      case 0: br.ReadOneBit(); break;
      case 1: br.ReadUBitLong((ops[i] >> 5) * 4 + 1); break;
      case 2: br.ReadSBitLong((ops[i] >> 5) * 4 + 1); break;
      case 3: br.ReadUBitVar(); break;
      case 4: br.ReadVarInt32(); break;
      case 5: br.ReadVarInt64(); break;
      case 6: br.ReadBitCoord(); break;
      case 7: br.ReadBitCoordMP((ops[i] & 0x20) != 0, (ops[i] & 0x40) != 0); break;
      case 8: br.ReadBitFloat(); break;
      case 9: br.ReadBitNormal(); break;
      case 10: { Vector v; br.ReadBitVec3Coord(v); break; }
      case 11: { Vector v; br.ReadBitVec3Normal(v); break; }
      case 12: { QAngle a; br.ReadBitAngles(a); break; }
      case 13: br.ReadBitAngle((ops[i] >> 5) * 4 + 1); break;
      case 14: br.ReadLongLong(); break;
      case 15: br.ReadFloat(); break;
      case 16: br.ReadBytes(bytes, (ops[i] >> 5) * 8); break;
      case 17: br.ReadString(str, sizeof(str), (ops[i] & 0x20) != 0); break;
      case 18: { bool ov = false; char *s = br.ReadAndAllocateString(&ov); delete[] s; break; }
      case 19: br.ReadBits(bytes, ((ops[i] >> 5) + 1) * 8); break;
      case 20: br.ReadBitsClamped(bytes, ((ops[i] >> 5) + 1) * 16); break;
      case 21: br.SeekRelative((ops[i] >> 5) * 3 - 8); break;
      case 22: br.ReadBitCoordBits(); break;
      case 23: br.ReadBitCoordMPBits((ops[i] & 0x20) != 0, (ops[i] & 0x40) != 0); break;
      default: br.ReadWord(); break;
    }
    if (br.IsOverflowed()) break;
  }
  free(copy);
  return 0;
}
