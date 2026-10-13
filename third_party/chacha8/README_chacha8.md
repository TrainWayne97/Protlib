# third_party/chacha8

ChaCha8 (8 Runden) aus dem eSTREAM-Paket von D. J. Bernstein, eingebunden ueber
die eSTREAM-Schnittstelle (`ecrypt-sync.h`). Alle Dateien in diesem Verzeichnis
sind unveraenderte Originale. Anpassungen am Code gibt es nicht; Compilerwarnungen
werden im Makefile nur fuer dieses Verzeichnis abgeschaltet.

Quelle: https://cr.yp.to/chacha.html


## Dateien

| Datei | Aufgabe |
|---|---|
| `chacha-ref.c` | Variante `ref`, Referenzimplementierung |
| `chacha-regs.c` | Variante `regs`, Zustand in Registervariablen |
| `chacha-merged.c` | Variante `merged`, zusammengefuehrte Rundenfunktion |
| `ecrypt-sync.h` | eSTREAM-Schnittstelle (`ECRYPT_keysetup`, `ECRYPT_ivsetup`, `ECRYPT_encrypt_bytes`, ...) |
| `ecrypt-portable.h` | Typen (`u8`, `u32`) und Makros fuer Rotation und Byte-Zugriffe |
| `ecrypt-config.h` | Erkennung von Byte-Reihenfolge und Typbreiten, wird von `ecrypt-portable.h` eingebunden |
| `ecrypt-machine.h` | Platz fuer plattformspezifische Makros, wird von `ecrypt-portable.h` eingebunden |

Die drei Quelldateien `chacha-*.c` sind austauschbar und liefern bei gleichem
Schluessel und gleicher IV dieselben Bytes. Die Variante waehlt das Makefile:

    make test CHACHA8_IMPL=ref        # Standard
    make test CHACHA8_IMPL=regs
    make test CHACHA8_IMPL=merged

## Format

Schluessel 128 oder 256 Bit, IV (Nonce) 64 Bit, Zaehler 64 Bit. Der Zaehler
beginnt bei jedem `ECRYPT_ivsetup` bei 0. Gerechnet werden 8 Runden.

## Hinweise

- **Stueckelung.** Nach einem Aufruf mit einer Laenge, die kein Vielfaches von
  64 Byte ist, wird der Rest des Schluesselstromblocks verworfen. Aufrufe in
  beliebigen Stuecken ergeben deshalb nicht dasselbe wie ein einziger Aufruf.
  Das gleicht die Adapterschicht (`src/chacha8.c`) aus, nicht dieses
  Verzeichnis. `tests/test_chacha8.c` haelt das Verhalten des Backends fest.
- **Byte-Reihenfolge.** `ecrypt-config.h` erkennt auf x86-64 keine Byte-Reihenfolge
  (`ECRYPT_UNKNOWN`); `ecrypt-portable.h` verwendet dann byteweise Zugriffe.
  Das Ergebnis haengt damit weder von der Ausrichtung der Puffer noch von der
  Byte-Reihenfolge ab. Auf AArch64 (Raspberry Pi 3, Zynq UltraScale+) ist dies
  aus der Erkennungsliste in `ecrypt-config.h` zu erwarten, aber noch nicht
  ueberprueft.
- **Lizenz.** Die `chacha-*.c` tragen in der Kopfzeile den Vermerk "Public domain".


## Tests

Die Tests liegen in `tests/test_chacha8.c` und pruefen zehn veroeffentlichte
Testvektoren (128 und 256 Bit, 8 Runden), die Stueckelung in Vielfachen von 64
Byte, den In-place-Betrieb und den Roundtrip. Quelle der Vektoren: siehe
Kommentar in `tests/vectors/chacha8_vectors.h`.
