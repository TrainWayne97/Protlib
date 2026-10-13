/* Interne Schnittstelle des ChaCha8-Adapters (nicht Teil von include/prot).
 *
 * Der Adapter bildet prot_config auf die eSTREAM-Schnittstelle in
 * third_party/chacha8 ab. Er puffert den Rest eines angefangenen
 * Schluesselstromblocks im Zustand, sodass die Verarbeitung unabhaengig
 * davon ist, in welchen Stuecken prot_process() aufgerufen wird. */

#ifndef PROT_SRC_CHACHA8_H
#define PROT_SRC_CHACHA8_H

#include <stddef.h>
#include <stdint.h>

#include "prot/prot.h"

typedef struct prot_chacha8_state prot_chacha8_state;

/* Prueft Schluessel- und IV-Laenge (16/32 bzw. 8 Byte) und legt den Zustand
 * an. Liefert PROT_OK, PROT_ERR_INVALID_ARG oder PROT_ERR_NOMEM. */
int  prot_chacha8_create(const prot_config *cfg, prot_chacha8_state **out);

/* Verknuepft len Bytes per XOR mit dem Schluesselstrom. Die Argumente sind
 * bereits von prot_process() geprueft. Liefert PROT_OK oder PROT_ERR_LIMIT;
 * im Fehlerfall bleiben Ausgabe und Zustand unveraendert. */
int  prot_chacha8_process(prot_chacha8_state *st, const uint8_t *in,
                          uint8_t *out, size_t len);

/* Loescht Schluesselmaterial und Schluesselstromrest, gibt den Zustand frei.
 * NULL ist erlaubt. */
void prot_chacha8_destroy(prot_chacha8_state *st);

/* Nur fuer Tests: setzt den Blockzaehler (Zustandswoerter 12/13 des Backends
 * und die Zaehlung im Adapter) auf blocks und verwirft den gepufferten Rest.
 * Damit laesst sich das Erreichen der Obergrenze pruefen, ohne 2^70 Byte zu
 * verarbeiten. */
void prot_chacha8_test_set_block_counter(prot_chacha8_state *st, uint64_t blocks);

#endif
