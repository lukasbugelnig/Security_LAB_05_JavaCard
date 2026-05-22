# Security_LAB_05_JavaCard

## Stand W01.4

Implementiert ist die elektronische Geldboerse im bisherigen MyFirst-Slot:

- `VERIFY` (`INS 20`): P2 `01`/`02`/`03` waehlt PIN1/PIN2/PIN3, OwnerPIN mit 3 Versuchen.
- `CHANGE` (`INS 24`): PINs werden einmalig in der Reihenfolge PIN1, PIN2, PIN3 geaendert.
- `STATUS` (`INS F2`): liefert PIN-Flags, verbleibende Versuche, Userdaten-Flag und Kartenblockade.
- `MODIFY` (`INS D6`): schreibt Vorname, Nachname und Geburtsdatum nach PIN1.
- `READ` (`INS B6`): liest Benutzerdaten nach PIN1 oder PIN2.
- `AGE18` (`INS 18`): prueft Alter ab 18 Jahren mit aktuellem Datum als APDU-Parameter.
- `CREDIT` (`INS 30`): laedt nach PIN2, mit Euro/Cent und Overflow-Schutz bis EUR 9999,99.
- `DEBIT` (`INS 40`): bucht nach PIN3 ab, mit Underflow-Schutz.
- `BALANCE` (`INS 50`): liefert das Guthaben ohne PIN.
- `UNLOCK` (`INS 78`): entsperrt PIN3 nach drei Fehlversuchen mit 8-stelligem PUK.
- `LOG` (`INS 76`): liest nach PIN3 die letzten 10 Transaktionen als FIFO.

Nicht umgesetzt sind nur die optionalen Punkte aus W01.4i und die optionale PC-Komponente W01.5.

## APDU-Formate

- PINs und PUK werden als ASCII-Ziffern uebergeben, Default PIN1/PIN2/PIN3 ist `0000`, Default PUK ist `00000000`.
- Benutzerdaten: `<Vorname> FF <Nachname> FF <TTMMJJJJ> FF`.
- Betraege: `EUR_hi EUR_lo CENT`, z.B. `00 0C 22` fuer EUR 12,34.
- `STATUS` liefert 9 Byte: `pin1Changed pin2Changed pin3Changed triesPIN1 triesPIN2 triesPIN3 triesPUK userDataSet cardBlocked`.
- `LOG` liefert pro Eintrag 4 Byte: `type EUR_hi EUR_lo CENT`, mit `01` fuer Credit und `02` fuer Debit.

## Testskript

`workspace_JC/Java Card Applet Samples/macros/Purse.macro` ist als automatischer Kompletttest fuer W01.4 angelegt. Es prueft:

- PIN-Management inklusive falscher PIN, falscher Reihenfolge und wiederholtem CHANGE.
- Schreiben/Lesen der Benutzerdaten und zu lange MODIFY-Daten mit `6A 80`.
- `AGE18` mit Datum `22.05.2026`.
- `CREDIT`, `DEBIT`, `BALANCE`, Cent-Uebertrag, Overflow und Underflow.
- PIN3-geschuetztes Transaktionslog.
- Sperren von PIN3 nach drei Fehlversuchen und `UNLOCK` mit PUK.

## Plan Tag 1

1. Projekt in der JavaCard Suite oeffnen und Simulator `Convego Join / SmartCafe Expert 5.0 (Simulation)` verbinden.
2. `MyFirstApplet.java` lesen: Dispatcher, APDU-Offsets, `receiveExact`, OwnerPIN-Verwendung und Datenformate verstehen.
3. Applet im Simulator mit `Run` installieren und `Purse.macro` komplett ausfuehren.
4. Bei Fehlern zuerst SW im Macro-Log mit den erwarteten Werten vergleichen, dann die betreffende Methode im Debugger pruefen.
5. Nach erfolgreichem Simulatorlauf dieselbe Macro-Datei auf der echten Karte testen.
6. Fuer die Abgabe die Log-Ausgabe sichern und die kritischen Code-Stellen erklaeren koennen: PIN-Wechsel, Bounds-Checks bei MODIFY, Overflow/Underflow, PUK-Sperre und FIFO-Log.
