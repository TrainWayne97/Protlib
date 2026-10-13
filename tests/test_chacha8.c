/* Tests fuer das ChaCha8-Backend (eSTREAM-Referenzcode in third_party/chacha8).
 *
 * Geprueft werden
 *   1. Known-Answer-Tests: zehn veroeffentlichte Testvektoren (128 und 256 Bit)
 *   2. Stueckelung in Vielfachen von 64 Byte ergibt dasselbe wie ein Aufruf
 *   3. In-place (identische Puffer) ergibt dasselbe wie getrennte Puffer
 *   4. Roundtrip: Ver- und Entschluesseln ergibt wieder die Nachricht
 *   5. Charakterisierung: beliebige Stueckelung ist beim Backend NICHT
 *      transparent. Die Adapterschicht muss das ausgleichen (siehe unten).
 *
 * Die Tests rufen die ECRYPT-Schnittstelle direkt auf und laufen deshalb
 * unabhaengig von der einheitlichen Schnittstelle prot_*. */

#include <stddef.h>

#include "ecrypt-sync.h"
#include "test_common.h"
#include "vectors/chacha8_vectors.h"

#define MSG_MAX 1024

static void fill_key_iv(u8 key[32], u8 iv[8])
{
  size_t i;
  for (i = 0; i < 32; i++) key[i] = (u8)i;
  for (i = 0; i < 8; i++) iv[i] = (u8)(0xA0 + i);
}

static void fill_message(u8 *m, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) m[i] = (u8)((i * 7 + 3) & 0xff);
}

/* Verschluesselt n Bytes mit festem Schluessel und IV in Stuecken der Groesse
 * chunk (chunk == 0: ein einziger Aufruf). in == out ist erlaubt. */
static void crypt_chunked(const u8 *in, u8 *out, size_t n, size_t chunk)
{
  ECRYPT_ctx ctx;
  u8 key[32], iv[8];
  size_t off, len;

  fill_key_iv(key, iv);
  ECRYPT_keysetup(&ctx, key, 256, 64);
  ECRYPT_ivsetup(&ctx, iv);

  if (chunk == 0 || chunk > n) {
    ECRYPT_encrypt_bytes(&ctx, in, out, (u32)n);
    return;
  }
  for (off = 0; off < n; off += chunk) {
    len = (n - off < chunk) ? (n - off) : chunk;
    ECRYPT_encrypt_bytes(&ctx, in + off, out + off, (u32)len);
  }
}

static void test_known_answer(void)
{
  size_t i;
  for (i = 0; i < CHACHA8_VECTOR_COUNT; i++) {
    const chacha8_vector *v = &CHACHA8_VECTORS[i];
    ECRYPT_ctx ctx;
    u8 ks[64];

    ECRYPT_keysetup(&ctx, v->key, v->keybits, 64);
    ECRYPT_ivsetup(&ctx, v->iv);
    ECRYPT_keystream_bytes(&ctx, ks, 64);
    CHECK_MEM(v->name, ks, v->keystream, 64);
  }
}

static void test_chunks_multiple_of_64(void)
{
  static const size_t chunks[] = { 64, 128, 192, 512, 960 };
  u8 plain[MSG_MAX], single[MSG_MAX], chunked[MSG_MAX];
  size_t i, n = 1000;

  fill_message(plain, n);
  crypt_chunked(plain, single, n, 0);
  for (i = 0; i < sizeof chunks / sizeof chunks[0]; i++) {
    crypt_chunked(plain, chunked, n, chunks[i]);
    CHECK_MEM("Stuecke in Vielfachen von 64 Byte", chunked, single, n);
  }
}

static void test_in_place(void)
{
  static const size_t lens[] = { 1, 63, 64, 65, 1000 };
  u8 plain[MSG_MAX], separate[MSG_MAX], inplace[MSG_MAX];
  size_t i, j;

  for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
    size_t n = lens[i];
    fill_message(plain, n);
    crypt_chunked(plain, separate, n, 0);
    for (j = 0; j < n; j++) inplace[j] = plain[j];
    crypt_chunked(inplace, inplace, n, 0);
    CHECK_MEM("in-place gegen getrennte Puffer", inplace, separate, n);
  }
}

static void test_roundtrip(void)
{
  static const size_t lens[] = { 0, 1, 63, 64, 65, 127, 128, 129, 1000 };
  u8 plain[MSG_MAX], enc[MSG_MAX], dec[MSG_MAX];
  size_t i;

  for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
    size_t n = lens[i];
    fill_message(plain, n);
    crypt_chunked(plain, enc, n, 0);
    crypt_chunked(enc, dec, n, 0);
    CHECK_MEM("Roundtrip", dec, plain, n);
    if (n >= 16) CHECK(memcmp(enc, plain, n) != 0);   /* Chiffrat darf nicht die Nachricht sein */
  }
}

/* Charakterisierung des Backends: Nach einem Aufruf mit einer Laenge, die kein
 * Vielfaches von 64 ist, wird der Rest des Schluesselstroms verworfen. Stuecke
 * von 50 Byte ergeben deshalb ein anderes Ergebnis als ein einziger Aufruf.
 * Die Schnittstelle prot_process() verspricht Unabhaengigkeit von der
 * Stueckelung; die Adapterschicht muss den Rest zwischenspeichern.
 * Wird das Backend gegen eines mit beliebiger Stueckelung getauscht, entfaellt
 * diese Pruefung. */
static void test_odd_chunking_is_not_transparent(void)
{
  u8 plain[MSG_MAX], single[MSG_MAX], chunked[MSG_MAX];
  size_t n = 200;

  fill_message(plain, n);
  crypt_chunked(plain, single, n, 0);
  crypt_chunked(plain, chunked, n, 50);
  CHECK(memcmp(single, chunked, n) != 0);
}

int main(void)
{
  ECRYPT_init();

  test_known_answer();
  test_chunks_multiple_of_64();
  test_in_place();
  test_roundtrip();
  test_odd_chunking_is_not_transparent();

  return test_summary("test_chacha8");
}
