// Known-answer functional tests for the Source SDK code the fuzz targets cover (tier1 parsers/codecs, bitbuf,
// checksums) and the vendored libspng. Built by mayhem/build.sh with the project's normal flags; run by test.sh.
#include "tier1/KeyValues.h"
#include "tier1/keyvaluesjson.h"
#include "tier1/utlbuffer.h"
#include "tier1/lzss.h"
#include "tier1/snappy.h"
#include "tier1/bitbuf.h"
#include "tier1/checksum_crc.h"
#include "tier1/checksum_md5.h"
#include "tier1/checksum_sha1.h"
#include "tier1/strtools.h"
#include "spng/spng.h"
#include <zlib.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

static int g_pass = 0, g_fail = 0;
static FILE *g_out; // results go to a file: tier0 writes ANSI escapes to stdout and would corrupt line parsing
#define CHECK(name, cond)                                                      \
  do {                                                                         \
    if (cond) { g_pass++; fprintf(g_out, "PASS %s\n", name); }                         \
    else { g_fail++; fprintf(g_out, "FAIL %s (%s:%d)\n", name, __FILE__, __LINE__); } \
  } while (0)

static std::string Save(KeyValues *kv, bool sort = false) {
  CUtlBuffer out(0, 0, CUtlBuffer::TEXT_BUFFER);
  kv->RecursiveSaveToFile(out, 0, sort);
  return std::string((const char *)out.Base(), out.TellPut());
}

static void TestKeyValues() {
  const char *text = "\"Weapon\"\n{\n\t\"damage\" \"42\"\n\t\"speed\" \"1.5\"\n\t\"name\" \"crowbar\"\n"
                     "\t\"Sounds\"\n\t{\n\t\t\"single\" \"Weapon.Hit\"\n\t}\n}\n";
  KeyValues *kv = new KeyValues("root");
  CUtlBuffer buf(text, (int)strlen(text), CUtlBuffer::READ_ONLY | CUtlBuffer::TEXT_BUFFER);
  CHECK("kv_load", kv->LoadFromBuffer("t", buf));
  KeyValues *w = kv;
  CHECK("kv_root_name", strcmp(kv->GetName(), "Weapon") == 0);
  if (w) {
    CHECK("kv_int", w->GetInt("damage") == 42);
    CHECK("kv_float", w->GetFloat("speed") == 1.5f);
    CHECK("kv_string", strcmp(w->GetString("name"), "crowbar") == 0);
    CHECK("kv_subkey", strcmp(w->GetString("Sounds/single"), "Weapon.Hit") == 0);
    CHECK("kv_default", w->GetInt("missing", 7) == 7);
    CHECK("kv_text_roundtrip", Save(kv).find("\"damage\"\t\t\"42\"") != std::string::npos);
    CUtlBuffer bin;
    CHECK("kv_bin_write", kv->WriteAsBinary(bin));
    KeyValues *back = new KeyValues("root");
    CUtlBuffer rd(bin.Base(), bin.TellPut(), CUtlBuffer::READ_ONLY);
    CHECK("kv_bin_read", back->ReadAsBinary(rd));
    CHECK("kv_bin_roundtrip_equal", Save(back, true) == Save(kv, true));
    back->deleteThis();
  }
  KeyValues *part = new KeyValues("root");
  const char *broken = "\"a\" { \"b\" \"c\" ";
  CUtlBuffer bb(broken, (int)strlen(broken), CUtlBuffer::READ_ONLY | CUtlBuffer::TEXT_BUFFER);
  part->LoadFromBuffer("t", bb);
  CHECK("kv_truncated_keeps_complete_pair", strcmp(part->GetString("b"), "c") == 0);
  part->deleteThis();
  kv->deleteThis();
}

static void TestJson() {
  const char *json = "{\"name\":\"gordon\",\"hp\":100,\"alive\":true,\"inv\":[\"crowbar\",\"pistol\"]}";
  KeyValuesJSONParser p(json, (int)strlen(json));
  KeyValues *kv = p.ParseFile();
  CHECK("json_parse", kv != NULL);
  if (kv) {
    CHECK("json_string", strcmp(kv->GetString("name"), "gordon") == 0);
    CHECK("json_int", kv->GetInt("hp") == 100);
    KeyValues *inv = kv->FindKey("inv");
    CHECK("json_array", inv && inv->GetFirstSubKey() && strcmp(inv->GetFirstSubKey()->GetString(), "crowbar") == 0);
    kv->deleteThis();
  }
  const char *bad = "{\"a\": [1, 2,";
  KeyValuesJSONParser p2(bad, (int)strlen(bad));
  KeyValues *k2 = p2.ParseFile();
  CHECK("json_rejects_truncated", k2 == NULL);
  if (k2) k2->deleteThis();
}

static void TestLzss() {
  std::vector<unsigned char> in;
  for (int i = 0; i < 4096; i++) in.push_back((unsigned char)("abcabcabd"[i % 9]));
  CLZSS lz;
  unsigned int csize = 0;
  unsigned char *comp = lz.Compress(in.data(), (int)in.size(), &csize);
  CHECK("lzss_compress", comp != NULL && csize < in.size() / 4);
  if (comp) {
    CHECK("lzss_is_compressed", CLZSS::IsCompressed(comp));
    CHECK("lzss_actual_size", CLZSS::GetActualSize(comp) == in.size());
    std::vector<unsigned char> out(in.size());
    CHECK("lzss_uncompress_len", lz.Uncompress(comp, out.data()) == in.size());
    CHECK("lzss_roundtrip", out == in);
    std::vector<unsigned char> out2(in.size());
    CHECK("lzss_safe_uncompress", lz.SafeUncompress(comp, csize, out2.data(), (unsigned)in.size()) == in.size() && out2 == in);
    CHECK("lzss_safe_rejects_short_buffer", lz.SafeUncompress(comp, csize, out2.data(), 16) == 0);
    free(comp);
  }
}

static void TestSnappy() {
  // Hand-assembled stream: length 11, literal "hello " (6 bytes), then a copy of length 5 at offset 6.
  const unsigned char stream[] = {11, 5 << 2, 'h', 'e', 'l', 'l', 'o', ' ', ((5 - 4) << 2) | 1, 6};
  std::string out;
  CHECK("snappy_valid", snappy::IsValidCompressedBuffer((const char *)stream, sizeof(stream)));
  CHECK("snappy_uncompress", snappy::Uncompress((const char *)stream, sizeof(stream), &out));
  CHECK("snappy_known_output", out == "hello hello");
  std::string big(10000, 'x'), comp, back;
  snappy::Compress(big.data(), big.size(), &comp);
  CHECK("snappy_compresses", comp.size() < 1000);
  CHECK("snappy_roundtrip", snappy::Uncompress(comp.data(), comp.size(), &back) && back == big);
  const unsigned char trunc[] = {20, 5 << 2, 'a'};
  CHECK("snappy_rejects_truncated", !snappy::IsValidCompressedBuffer((const char *)trunc, sizeof(trunc)));
}

static void TestBitbuf() {
  unsigned char mem[128];
  memset(mem, 0, sizeof(mem));
  bf_write bw(mem, sizeof(mem));
  bw.WriteUBitLong(5, 3);
  bw.WriteSBitLong(-7, 6);
  bw.WriteOneBit(1);
  bw.WriteVarInt32(300);
  bw.WriteString("barnacle");
  bw.WriteBitFloat(3.25f);
  bf_read br(mem, sizeof(mem));
  CHECK("bitbuf_ubit", br.ReadUBitLong(3) == 5);
  CHECK("bitbuf_sbit", br.ReadSBitLong(6) == -7);
  CHECK("bitbuf_onebit", br.ReadOneBit() == 1);
  CHECK("bitbuf_varint", br.ReadVarInt32() == 300);
  char s[32];
  CHECK("bitbuf_string", br.ReadString(s, sizeof(s)) && strcmp(s, "barnacle") == 0);
  CHECK("bitbuf_float", br.ReadBitFloat() == 3.25f);
  CHECK("bitbuf_no_overflow", !br.IsOverflowed());
  bf_read shortbuf(mem, 1);
  shortbuf.ReadUBitLong(32);
  CHECK("bitbuf_overflow_detected", shortbuf.IsOverflowed());
}

static void TestChecksums() {
  CHECK("crc32_abc", CRC32_ProcessSingleBuffer("abc", 3) == 0x352441c2u);
  MD5Value_t md5;
  MD5_ProcessSingleBuffer("abc", 3, md5);
  char hex[33];
  for (int i = 0; i < 16; i++) snprintf(hex + i * 2, 3, "%02x", md5.bits[i]);
  CHECK("md5_abc", strcmp(hex, "900150983cd24fb0d6963f7d28e17f72") == 0);
  CSHA1 sha;
  unsigned char abc[3] = {'a', 'b', 'c'};
  sha.Update(abc, 3);
  sha.Final();
  unsigned char dg[20];
  sha.GetHash(dg);
  char sh[41];
  for (int i = 0; i < 20; i++) snprintf(sh + i * 2, 3, "%02x", dg[i]);
  CHECK("sha1_abc", strcmp(sh, "a9993e364706816aba3e25717850c26c9cd0d89d") == 0);
}

static void TestStrtools() {
  char buf[64];
  V_strncpy(buf, "Hello", sizeof(buf));
  V_strupr(buf);
  CHECK("strtools_upr", strcmp(buf, "HELLO") == 0);
  CHECK("strtools_stricmp", V_stricmp("AbC", "aBc") == 0);
  V_FixSlashes(strcpy(buf, "a/b/c"), '\\');
  CHECK("strtools_fixslashes", strcmp(buf, "a\\b\\c") == 0);
  V_StripExtension("models/crate.mdl", buf, sizeof(buf));
  CHECK("strtools_stripext", strcmp(buf, "models/crate") == 0);
}

static void TestSpng() {
  const char *src = getenv("SRC");
  std::string path = std::string(src ? src : "/mayhem") + "/src/thirdparty/libspng/tests/images/basn6a08.png";
  FILE *f = fopen(path.c_str(), "rb");
  CHECK("spng_open_image", f != NULL);
  if (!f) return;
  spng_ctx *ctx = spng_ctx_new(0);
  spng_set_png_file(ctx, f);
  struct spng_ihdr ihdr;
  CHECK("spng_ihdr", spng_get_ihdr(ctx, &ihdr) == 0);
  CHECK("spng_dims", ihdr.width == 32 && ihdr.height == 32);
  CHECK("spng_color", ihdr.color_type == SPNG_COLOR_TYPE_TRUECOLOR_ALPHA && ihdr.bit_depth == 8);
  size_t sz = 0;
  spng_decoded_image_size(ctx, SPNG_FMT_RGBA8, &sz);
  CHECK("spng_decoded_size", sz == 32 * 32 * 4);
  std::vector<unsigned char> px(sz);
  CHECK("spng_decode", spng_decode_image(ctx, px.data(), sz, SPNG_FMT_RGBA8, 0) == 0);
  CHECK("spng_pixel_crc", crc32(0, px.data(), (uInt)sz) == 0xa74df32cu);
  spng_ctx_free(ctx);
  fclose(f);

  std::vector<unsigned char> img(8 * 8 * 4);
  for (size_t i = 0; i < img.size(); i++) img[i] = (unsigned char)(i * 7 + 3);
  spng_ctx *enc = spng_ctx_new(SPNG_CTX_ENCODER);
  spng_set_option(enc, SPNG_ENCODE_TO_BUFFER, 1);
  struct spng_ihdr eh = {};
  eh.width = 8; eh.height = 8; eh.bit_depth = 8; eh.color_type = SPNG_COLOR_TYPE_TRUECOLOR_ALPHA;
  spng_set_ihdr(enc, &eh);
  CHECK("spng_encode", spng_encode_image(enc, img.data(), img.size(), SPNG_FMT_PNG, SPNG_ENCODE_FINALIZE) == 0);
  size_t plen = 0;
  int err = 0;
  void *png = spng_get_png_buffer(enc, &plen, &err);
  CHECK("spng_encoded_buffer", png != NULL && plen > 8 && memcmp(png, "\x89PNG\r\n\x1a\n", 8) == 0);
  if (png) {
    spng_ctx *dec = spng_ctx_new(0);
    spng_set_png_buffer(dec, png, plen);
    std::vector<unsigned char> rt(img.size());
    CHECK("spng_roundtrip_decode", spng_decode_image(dec, rt.data(), rt.size(), SPNG_FMT_RGBA8, 0) == 0);
    CHECK("spng_roundtrip_equal", rt == img);
    spng_ctx_free(dec);
    free(png);
  }
  spng_ctx_free(enc);
  std::vector<unsigned char> garbage(64, 0x41);
  spng_ctx *g = spng_ctx_new(0);
  spng_set_png_buffer(g, garbage.data(), garbage.size());
  CHECK("spng_rejects_garbage", spng_get_ihdr(g, &ihdr) != 0);
  spng_ctx_free(g);
}

int main(int argc, char **argv) {
  g_out = argc > 1 ? fopen(argv[1], "w") : stdout;
  if (!g_out) return 2;
  TestKeyValues();
  TestJson();
  TestLzss();
  TestSnappy();
  TestBitbuf();
  TestChecksums();
  TestStrtools();
  TestSpng();
  fprintf(g_out, "SUMMARY passed=%d failed=%d\n", g_pass, g_fail);
  fclose(g_out);
  return g_fail ? 1 : 0;
}
