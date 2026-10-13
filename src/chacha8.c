/* ChaCha8-Adapter: bildet die einheitliche Schnittstelle prot_* auf die
 * eSTREAM-Implementierung in third_party/chacha8 ab.
 *
 * Aufgaben des Adapters:
 *   - Schluessel (16 oder 32 Byte) und Nonce (8 Byte) pruefen,
 *   - den Rest eines angefangenen 64-Byte-Schluesselstromblocks puffern
 *     (das Backend verwirft ihn), damit die Ausgabe nicht von der
 *     Stueckelung der Aufrufe abhaengt,
 *   - Laengen ueber dem 32-Bit-Bereich des Backends in Teilaufrufe
 *     zerlegen, deren Laenge ein Vielfaches von 64 Byte ist,
 *   - die Obergrenze von 2^64 Bloecken (2^70 Byte) pro Schluessel und Nonce
 *     durchsetzen; das Backend zaehlt danach unbemerkt bei 0 weiter, was den
 *     Schluesselstrom wiederholen wuerde,
 *   - Schluesselmaterial beim Zerstoeren loeschen.
 */

/* explicit_bzero ist nicht Teil von C11; glibc (ab 2.25) deklariert es nur
 * mit _DEFAULT_SOURCE. Muss vor dem ersten Include stehen.
 * OFFEN: Verfuegbarkeit auf Raspberry Pi 3 und Zynq pruefen. */
#define _DEFAULT_SOURCE

#include <stdlib.h>
#include <string.h>

#include "chacha8.h"
#include "ecrypt-sync.h"

#define CHACHA8_BLOCK 64u

/* Groesste Laenge, die ECRYPT_encrypt_bytes (u32) annimmt und die ein
 * Vielfaches der Blocklaenge ist. Nur volle Bloecke duerfen an das Backend
 * gehen, sonst verwirft es den Rest eines Blocks. */
#define CHACHA8_CHUNK_MAX ((size_t)0xFFFFFFC0u)

struct prot_chacha8_state {
  ECRYPT_ctx ctx;                 /* enthaelt Schluessel, Nonce, Blockzaehler */
  uint8_t    ks[CHACHA8_BLOCK];   /* zuletzt erzeugter Schluesselstromblock */
  size_t     ks_pos;              /* naechstes unverbrauchtes Byte in ks;
                                     CHACHA8_BLOCK bedeutet: kein Rest */
  uint64_t   blocks_used;         /* erzeugte Bloecke modulo 2^64 */
  int        exhausted;           /* 1, sobald 2^64 Bloecke erzeugt wurden */
};

int prot_chacha8_create(const prot_config *cfg, prot_chacha8_state **out)
{
  prot_chacha8_state *st;

  if (cfg->key == NULL || cfg->iv == NULL)
    return PROT_ERR_INVALID_ARG;
  /* Das Backend prueft die Schluessellaenge nicht: jeder Wert ausser 256 Bit
   * wuerde als 128 Bit behandelt. Die Pruefung hier ist daher die einzige. */
  if (cfg->key_len != 16 && cfg->key_len != 32)
    return PROT_ERR_INVALID_ARG;
  if (cfg->iv_len != 8)
    return PROT_ERR_INVALID_ARG;

  st = calloc(1, sizeof *st);
  if (st == NULL)
    return PROT_ERR_NOMEM;

  ECRYPT_init();
  ECRYPT_keysetup(&st->ctx, cfg->key, (u32)(cfg->key_len * 8u), 64);
  ECRYPT_ivsetup(&st->ctx, cfg->iv);
  st->ks_pos      = CHACHA8_BLOCK;
  st->blocks_used = 0;
  st->exhausted   = 0;

  *out = st;
  return PROT_OK;
}

/* Prueft, ob noch 'needed' Bloecke erzeugt werden duerfen. */
static int blocks_available(const prot_chacha8_state *st, uint64_t needed)
{
  if (needed == 0)
    return 1;
  if (st->exhausted)
    return 0;
  if (st->blocks_used == 0)
    return 1;                            /* noch 2^64 Bloecke frei */
  return needed <= (uint64_t)0 - st->blocks_used;   /* 2^64 - blocks_used */
}

int prot_chacha8_process(prot_chacha8_state *st, const uint8_t *in,
                         uint8_t *out, size_t len)
{
  size_t   rest_in_ks, n, i, full;
  uint64_t needed = 0;

  if (len == 0)
    return PROT_OK;

  /* Zuerst pruefen, wie viele neue Bloecke noetig sind. Reicht das Kontingent
   * nicht, wird abgebrochen, bevor ein Byte veraendert wurde. */
  rest_in_ks = CHACHA8_BLOCK - st->ks_pos;
  if (len > rest_in_ks) {
    size_t r = len - rest_in_ks;
    needed = (uint64_t)(r / CHACHA8_BLOCK) + (r % CHACHA8_BLOCK != 0);
  }
  if (!blocks_available(st, needed))
    return PROT_ERR_LIMIT;

  /* 1. Rest des zuletzt erzeugten Blocks verbrauchen. */
  n = (len < rest_in_ks) ? len : rest_in_ks;
  for (i = 0; i < n; i++)
    out[i] = in[i] ^ st->ks[st->ks_pos + i];
  st->ks_pos += n;
  in  += n;
  out += n;
  len -= n;

  /* 2. Volle Bloecke direkt im Backend verarbeiten (in-place erlaubt). */
  full = len - (len % CHACHA8_BLOCK);
  while (full > 0) {
    size_t chunk = (full < CHACHA8_CHUNK_MAX) ? full : CHACHA8_CHUNK_MAX;
    ECRYPT_encrypt_bytes(&st->ctx, in, out, (u32)chunk);
    in   += chunk;
    out  += chunk;
    len  -= chunk;
    full -= chunk;
  }

  /* 3. Angefangenen Block erzeugen, benoetigten Teil verwenden, Rest puffern. */
  if (len > 0) {
    ECRYPT_keystream_bytes(&st->ctx, st->ks, CHACHA8_BLOCK);
    for (i = 0; i < len; i++)
      out[i] = in[i] ^ st->ks[i];
    st->ks_pos = len;
  }

  /* Genau 'needed' Bloecke wurden erzeugt. Ein Umlauf auf 0 heisst: alle
   * 2^64 Bloecke sind verbraucht. */
  if (needed > 0) {
    st->blocks_used += needed;
    if (st->blocks_used == 0)
      st->exhausted = 1;
  }
  return PROT_OK;
}

void prot_chacha8_destroy(prot_chacha8_state *st)
{
  if (st == NULL)
    return;
  /* Loescht Schluessel und Nonce (ctx) sowie den gepufferten Schluesselstrom.
   * Nicht erfasst: der Stapelpuffer 'output' im Backend, der den letzten
   * Schluesselstromblock enthaelt -- das liesse sich nur durch eine Aenderung
   * am unveraenderten Fremdcode beheben. */
  explicit_bzero(st, sizeof *st);
  free(st);
}

void prot_chacha8_test_set_block_counter(prot_chacha8_state *st, uint64_t blocks)
{
  st->ctx.input[12] = (u32)(blocks & 0xFFFFFFFFu);
  st->ctx.input[13] = (u32)(blocks >> 32);
  st->blocks_used   = blocks;
  st->exhausted     = 0;
  st->ks_pos        = CHACHA8_BLOCK;
}
