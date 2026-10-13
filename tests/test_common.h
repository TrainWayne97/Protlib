/* Minimaler Testrahmen ohne Fremdbibliothek.
 *
 * Jede Pruefung zaehlt mit. test_summary() liefert einen Rueckgabewert ungleich
 * null, sobald eine Pruefung fehlgeschlagen ist; main() gibt ihn weiter, damit
 * "make test" und die CI das Ergebnis auswerten koennen. */

#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stddef.h>
#include <stdio.h>
#include <string.h>

static int test_checks_total;
static int test_checks_failed;

static inline void test_check(int ok, const char *expr, const char *file, int line)
{
  test_checks_total++;
  if (!ok) {
    test_checks_failed++;
    fprintf(stderr, "  FEHLER %s:%d: %s\n", file, line, expr);
  }
}

static inline void test_check_mem(const char *label, const void *got, const void *want,
                                  size_t n, const char *file, int line)
{
  const unsigned char *g = got;
  const unsigned char *w = want;
  size_t i;

  test_checks_total++;
  for (i = 0; i < n; i++) {
    if (g[i] != w[i]) {
      test_checks_failed++;
      fprintf(stderr,
              "  FEHLER %s:%d: %s: erstes abweichendes Byte an Position %zu "
              "(erhalten 0x%02x, erwartet 0x%02x)\n",
              file, line, label, i, g[i], w[i]);
      return;
    }
  }
}

#define CHECK(cond) test_check((cond) != 0, #cond, __FILE__, __LINE__)
#define CHECK_MEM(label, got, want, n) \
  test_check_mem((label), (got), (want), (n), __FILE__, __LINE__)

static inline int test_summary(const char *name)
{
  printf("%s: %d Pruefungen, %d fehlgeschlagen\n", name, test_checks_total, test_checks_failed);
  return test_checks_failed ? 1 : 0;
}

#endif
