/* Tests fuer ChaCha8 ueber die einheitliche Schnittstelle prot_*.
 *
 * Geprueft werden
 *   1. Known-Answer-Tests: dieselben zehn Vektoren wie in test_chacha8.c,
 *      hier ueber prot_process() (Nullnachricht ergibt den Schluesselstrom)
 *   2. Stueckelung: beliebige Stueckgroessen ergeben dasselbe wie ein Aufruf
 *      (Zusage von Option A); Referenz ist ein einzelner Backend-Aufruf
 *   3. In-place gegen getrennte Puffer, auch bei ungerader Stueckelung
 *   4. Roundtrip mit getrennten Kontexten fuer Ver- und Entschluesseln
 *   5. Argumentpruefung: Schluessel-/IV-Laengen, NULL-Zeiger, Laenge 0,
 *      teilweise Ueberlappung, ungueltige Richtung, nicht angebundene Verfahren
 *   6. Obergrenze 2^64 Bloecke pro Nonce (ueber den Test-Einstieg des Adapters)
 *
 * Nicht abgedeckt: Laengen ueber 2^32 - 1 Byte (Zerlegung in Teilaufrufe),
 * da dafuer mehr als 4 GiB Puffer noetig waeren. */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "prot/prot.h"
#include "../src/chacha8.h"
#include "ecrypt-sync.h"
#include "test_common.h"
#include "vectors/chacha8_vectors.h"

#define MSG_MAX 2048

static uint8_t KEY[32];
static uint8_t IV[8];

static void fill_key_iv(void)
{
  size_t i;
  for (i = 0; i < 32; i++) KEY[i] = (uint8_t)i;
  for (i = 0; i < 8; i++) IV[i] = (uint8_t)(0xA0 + i);
}

static void fill_message(uint8_t *m, size_t n)
{
  size_t i;
  for (i = 0; i < n; i++) m[i] = (uint8_t)((i * 7 + 3) & 0xff);
}

static prot_config chacha_cfg(const uint8_t *key, size_t key_len,
                              const uint8_t *iv, size_t iv_len)
{
  prot_config cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.alg     = PROT_ALG_CHACHA8;
  cfg.dir     = PROT_DIR_ENCODE;
  cfg.variant = PROT_VARIANT_REF;
  cfg.key     = key;
  cfg.key_len = key_len;
  cfg.iv      = iv;
  cfg.iv_len  = iv_len;
  return cfg;
}

/* Referenz: ein einziger Backend-Aufruf ueber die ganze Laenge. */
static void reference(const uint8_t *in, uint8_t *out, size_t n)
{
  ECRYPT_ctx ctx;
  ECRYPT_keysetup(&ctx, KEY, 256, 64);
  ECRYPT_ivsetup(&ctx, IV);
  ECRYPT_encrypt_bytes(&ctx, in, out, (u32)n);
}

/* Verarbeitet n Bytes ueber prot_* in Stuecken aus 'sizes' (zyklisch). */
static int process_chunked(const uint8_t *in, uint8_t *out, size_t n,
                           const size_t *sizes, size_t count)
{
  prot_config cfg = chacha_cfg(KEY, 32, IV, 8);
  prot_ctx *ctx = NULL;
  size_t off = 0, k = 0;
  int rc = prot_ctx_create(&cfg, &ctx);

  if (rc != PROT_OK) return rc;
  while (off < n) {
    size_t len = sizes[k++ % count];
    if (len > n - off) len = n - off;
    rc = prot_process(ctx, in + off, out + off, len);
    if (rc != PROT_OK) break;
    off += len;
  }
  prot_ctx_destroy(ctx);
  return rc;
}

static void test_known_answer(void)
{
  size_t i;
  for (i = 0; i < CHACHA8_VECTOR_COUNT; i++) {
    const chacha8_vector *v = &CHACHA8_VECTORS[i];
    prot_config cfg = chacha_cfg(v->key, v->keybits / 8, v->iv, 8);
    prot_ctx *ctx = NULL;
    uint8_t zero[64] = {0}, ks[64];

    CHECK(prot_ctx_create(&cfg, &ctx) == PROT_OK);
    CHECK(prot_process(ctx, zero, ks, 64) == PROT_OK);
    CHECK_MEM(v->name, ks, v->keystream, 64);
    prot_ctx_destroy(ctx);
  }
}

static void test_chunking(void)
{
  static const size_t s1[]  = { 1 };
  static const size_t s50[] = { 50 };
  static const size_t s63[] = { 63 };
  static const size_t s65[] = { 65 };
  static const size_t mix[] = { 3, 61, 64, 1, 127, 0, 200, 5 };
  static const struct { const size_t *s; size_t c; const char *name; } cases[] = {
    { s1,  1, "Stuecke zu 1 Byte" },
    { s50, 1, "Stuecke zu 50 Byte" },
    { s63, 1, "Stuecke zu 63 Byte" },
    { s65, 1, "Stuecke zu 65 Byte" },
    { mix, sizeof mix / sizeof mix[0], "gemischte Stuecke inkl. Laenge 0" },
  };
  uint8_t plain[MSG_MAX], want[MSG_MAX], got[MSG_MAX];
  size_t i, n = 1500;

  fill_message(plain, n);
  reference(plain, want, n);
  for (i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    memset(got, 0, n);
    CHECK(process_chunked(plain, got, n, cases[i].s, cases[i].c) == PROT_OK);
    CHECK_MEM(cases[i].name, got, want, n);
  }
}

static void test_in_place(void)
{
  static const size_t mix[] = { 7, 64, 100, 1 };
  uint8_t plain[MSG_MAX], want[MSG_MAX], buf[MSG_MAX];
  size_t n = 1000;

  fill_message(plain, n);
  reference(plain, want, n);
  memcpy(buf, plain, n);
  CHECK(process_chunked(buf, buf, n, mix, sizeof mix / sizeof mix[0]) == PROT_OK);
  CHECK_MEM("in-place mit ungerader Stueckelung", buf, want, n);
}

static void test_roundtrip(void)
{
  static const size_t lens[] = { 1, 63, 64, 65, 1000 };
  static const size_t enc_s[] = { 50 };
  static const size_t dec_s[] = { 13, 200 };
  uint8_t plain[MSG_MAX], enc[MSG_MAX], dec[MSG_MAX];
  size_t i;

  for (i = 0; i < sizeof lens / sizeof lens[0]; i++) {
    size_t n = lens[i];
    fill_message(plain, n);
    /* Ver- und Entschluesseln bewusst mit unterschiedlicher Stueckelung */
    CHECK(process_chunked(plain, enc, n, enc_s, 1) == PROT_OK);
    CHECK(process_chunked(enc, dec, n, dec_s, 2) == PROT_OK);
    CHECK_MEM("Roundtrip mit unterschiedlicher Stueckelung", dec, plain, n);
  }
}

static void test_arguments(void)
{
  static const size_t bad_key[] = { 0, 15, 17, 24, 31, 33 };
  static const size_t bad_iv[]  = { 0, 7, 9, 12, 16 };
  uint8_t buf[128] = {0};
  prot_config cfg;
  prot_ctx *ctx = NULL;
  size_t i;

  /* ungueltige Schluessel- und IV-Laengen */
  for (i = 0; i < sizeof bad_key / sizeof bad_key[0]; i++) {
    cfg = chacha_cfg(KEY, bad_key[i], IV, 8);
    CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
    CHECK(ctx == NULL);
  }
  for (i = 0; i < sizeof bad_iv / sizeof bad_iv[0]; i++) {
    cfg = chacha_cfg(KEY, 32, IV, bad_iv[i]);
    CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
  }

  /* NULL-Zeiger bei create */
  cfg = chacha_cfg(NULL, 32, IV, 8);
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
  cfg = chacha_cfg(KEY, 32, NULL, 8);
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
  cfg = chacha_cfg(KEY, 32, IV, 8);
  CHECK(prot_ctx_create(NULL, &ctx) == PROT_ERR_INVALID_ARG);
  CHECK(prot_ctx_create(&cfg, NULL) == PROT_ERR_INVALID_ARG);

  /* Richtung: ungueltiger Wert abgelehnt, DECODE wie ENCODE akzeptiert */
  cfg.dir = (prot_dir)42;
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
  cfg.dir = PROT_DIR_DECODE;
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_OK);
  prot_ctx_destroy(ctx);
  ctx = NULL;

  /* nicht angebundene Verfahren und unbekannte Werte */
  cfg = chacha_cfg(KEY, 32, IV, 8);
  cfg.alg = PROT_ALG_AES;
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_UNSUPPORTED);
  cfg.alg = (prot_alg)42;
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_INVALID_ARG);
  cfg = chacha_cfg(KEY, 32, IV, 8);
  cfg.variant = (prot_variant)1;
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_ERR_UNSUPPORTED);

  /* process: NULL, Laenge 0, Ueberlappung */
  cfg = chacha_cfg(KEY, 32, IV, 8);
  CHECK(prot_ctx_create(&cfg, &ctx) == PROT_OK);
  CHECK(prot_process(NULL, buf, buf, 16) == PROT_ERR_INVALID_ARG);
  CHECK(prot_process(ctx, NULL, buf, 16) == PROT_ERR_INVALID_ARG);
  CHECK(prot_process(ctx, buf, NULL, 16) == PROT_ERR_INVALID_ARG);
  CHECK(prot_process(ctx, NULL, NULL, 0) == PROT_OK);
  CHECK(prot_process(ctx, buf, buf + 1, 16) == PROT_ERR_INVALID_ARG);
  CHECK(prot_process(ctx, buf + 1, buf, 16) == PROT_ERR_INVALID_ARG);
  CHECK(prot_process(ctx, buf, buf + 16, 16) == PROT_OK);   /* angrenzend */
  prot_ctx_destroy(ctx);

  prot_ctx_destroy(NULL);   /* darf nicht abstuerzen */
}

/* Obergrenze: Zaehler auf 2^64 - 1 setzen. Genau ein Block ist noch erlaubt;
 * danach muss jeder Aufruf, der einen neuen Block braucht, mit
 * PROT_ERR_LIMIT abbrechen und darf die Ausgabe nicht veraendern. Der
 * gepufferte Rest des letzten Blocks bleibt verwendbar. */
static void test_limit(void)
{
  prot_config cfg = chacha_cfg(KEY, 32, IV, 8);
  prot_chacha8_state *st = NULL;
  uint8_t in[128] = {0}, out[128], before[128];

  CHECK(prot_chacha8_create(&cfg, &st) == PROT_OK);
  prot_chacha8_test_set_block_counter(st, UINT64_MAX);

  /* Zwei Bloecke angefordert, nur einer frei: Abbruch ohne Aenderung */
  memset(out, 0xEE, sizeof out);
  memcpy(before, out, sizeof out);
  CHECK(prot_chacha8_process(st, in, out, 65) == PROT_ERR_LIMIT);
  CHECK_MEM("Ausgabe nach PROT_ERR_LIMIT unveraendert", out, before, sizeof out);

  /* Letzter Block: 40 Byte verwenden, 24 Byte bleiben gepuffert */
  CHECK(prot_chacha8_process(st, in, out, 40) == PROT_OK);
  CHECK(prot_chacha8_process(st, in, out, 24) == PROT_OK);
  CHECK(prot_chacha8_process(st, in, out, 1) == PROT_ERR_LIMIT);
  CHECK(prot_chacha8_process(st, in, out, 0) == PROT_OK);

  prot_chacha8_destroy(st);
}

int main(void)
{
  fill_key_iv();

  test_known_answer();
  test_chunking();
  test_in_place();
  test_roundtrip();
  test_arguments();
  test_limit();

  return test_summary("test_prot_chacha8");
}
