/* Einheitliche Schnittstelle prot_*: allgemeine Argumentpruefung und
 * Verteilung auf die Verfahren.
 *
 * Stand: nur ChaCha8 ist angebunden. AES und die LFSR-Scrambler liefern
 * PROT_ERR_UNSUPPORTED, bis ihre Adapter existieren. */

#include <stdint.h>
#include <stdlib.h>

#include "prot/prot.h"
#include "chacha8.h"

struct prot_ctx {
  prot_alg alg;
  union {
    prot_chacha8_state *chacha8;
  } u;
};

/* Teilweise Ueberlappung von Ein- und Ausgabe ist unzulaessig, vollstaendig
 * identische Puffer (in == out) sind erlaubt. Der Vergleich ueber uintptr_t
 * ist implementierungsdefiniert, auf den Zielplattformen (flacher
 * Adressraum) aber verlaesslich. */
static int partial_overlap(const uint8_t *in, const uint8_t *out, size_t len)
{
  uintptr_t a = (uintptr_t)in;
  uintptr_t b = (uintptr_t)out;

  if (a == b)
    return 0;
  return (a < b) ? (b - a < len) : (a - b < len);
}

int prot_ctx_create(const prot_config *cfg, prot_ctx **out)
{
  prot_ctx *ctx;
  int rc;

  if (cfg == NULL || out == NULL)
    return PROT_ERR_INVALID_ARG;
  *out = NULL;

  /* Die Richtung wird fuer alle Verfahren auf einen gueltigen Wert geprueft,
   * auch wenn ChaCha8 sie nicht auswertet (Ver- und Entschluesseln sind dort
   * dieselbe Operation). So fallen uninitialisierte Konfigurationen auf. */
  if (cfg->dir != PROT_DIR_ENCODE && cfg->dir != PROT_DIR_DECODE)
    return PROT_ERR_INVALID_ARG;
  if (cfg->variant != PROT_VARIANT_REF)
    return PROT_ERR_UNSUPPORTED;

  ctx = calloc(1, sizeof *ctx);
  if (ctx == NULL)
    return PROT_ERR_NOMEM;
  ctx->alg = cfg->alg;

  switch (cfg->alg) {
  case PROT_ALG_CHACHA8:
    rc = prot_chacha8_create(cfg, &ctx->u.chacha8);
    break;
  case PROT_ALG_AES:
  case PROT_ALG_LFSR_SERIAL:
  case PROT_ALG_LFSR_PARALLEL:
    rc = PROT_ERR_UNSUPPORTED;
    break;
  default:
    rc = PROT_ERR_INVALID_ARG;
    break;
  }

  if (rc != PROT_OK) {
    free(ctx);
    return rc;
  }
  *out = ctx;
  return PROT_OK;
}

int prot_process(prot_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len)
{
  if (ctx == NULL)
    return PROT_ERR_INVALID_ARG;
  if (len == 0)
    return PROT_OK;
  if (in == NULL || out == NULL)
    return PROT_ERR_INVALID_ARG;
  if (partial_overlap(in, out, len))
    return PROT_ERR_INVALID_ARG;

  switch (ctx->alg) {
  case PROT_ALG_CHACHA8:
    return prot_chacha8_process(ctx->u.chacha8, in, out, len);
  default:
    return PROT_ERR_UNSUPPORTED;
  }
}

void prot_ctx_destroy(prot_ctx *ctx)
{
  if (ctx == NULL)
    return;
  switch (ctx->alg) {
  case PROT_ALG_CHACHA8:
    prot_chacha8_destroy(ctx->u.chacha8);
    break;
  default:
    break;
  }
  free(ctx);
}
