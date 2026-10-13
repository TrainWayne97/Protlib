#ifndef PROT_H
#define PROT_H

#include <stddef.h>
#include <stdint.h>

/* Rückgabewerte: 0 = Erfolg, negativ = Fehler */
enum {
    PROT_OK              =  0,
    PROT_ERR_INVALID_ARG = -1,
    PROT_ERR_UNSUPPORTED = -2,
    PROT_ERR_NOMEM       = -3
};

typedef enum {
    PROT_ALG_AES,
    PROT_ALG_CHACHA8,
    PROT_ALG_LFSR_SERIAL,
    PROT_ALG_LFSR_PARALLEL
} prot_alg;

/* OFFEN: Richtung hängt von der LFSR-Bauart ab (selbstsynchronisierend
 * oder additiv). Bis das geklärt ist, bleibt der Parameter erhalten. */
typedef enum {
    PROT_DIR_ENCODE,
    PROT_DIR_DECODE
} prot_dir;

/* Vorerst nur die Referenzimplementierung ohne Hardwareunterstützung.
 * Weitere Varianten werden später ergänzt, ohne die Struktur zu ändern. */
typedef enum {
    PROT_VARIANT_REF
} prot_variant;

typedef struct {
    prot_alg      alg;
    prot_dir      dir;
    prot_variant  variant;

    /* AES und ChaCha/8 */
    const uint8_t *key;
    size_t         key_len;     /* AES: variierbar, ChaCha/8: festlegen */
    const uint8_t *iv;          /* Nonce bzw. IV */
    size_t         iv_len;

    /* LFSR-Scrambler */
    uint64_t       lfsr_seed;
    uint64_t       lfsr_poly;   /* OFFEN: Registerbreite und Darstellung */

    /* OFFEN: AES-Betriebsmodus, im Quelldokument nicht festgelegt */
} prot_config;

typedef struct prot_ctx prot_ctx;   /* undurchsichtig */

int  prot_ctx_create(const prot_config *cfg, prot_ctx **out);

/* Verarbeitet len Bytes. Der Zustand läuft über Aufrufe hinweg weiter.
 * in == out ist erlaubt, teilweise Überlappung ist unzulässig. */
int  prot_process(prot_ctx *ctx, const uint8_t *in, uint8_t *out, size_t len);

void prot_ctx_destroy(prot_ctx *ctx);

#endif