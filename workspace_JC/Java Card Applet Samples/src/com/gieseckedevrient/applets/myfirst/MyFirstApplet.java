/**********************************************************
 * Project:  Java Card Applet Samples - Electronic Purse
 * File:     MyFirstApplet.java
 *
 * System Security Lab SS 2026 (W01)
 *
 * Personalisierte elektronische Geldboerse, basierend auf dem
 * MyFirst-Beispiel von Giesecke & Devrient (C) 2010.
 * Belegt den MyFirst-Slot der JavaCard Suite (siehe FAQ S.10:
 * "beim Aus- bzw. Umbau von 'MyFirst' zur 'Purse' nicht erforderlich").
 *
 * Implementiert die Aufgaben W01.4 a-h:
 *   a) Analyse der MyFirst-Kommandos (siehe Original).
 *   b) MODIFY validiert Laengen -> 6A 80 statt 6F 00.
 *   c) Benutzerdaten in firstName/lastName/birthDate aufgeteilt
 *      (SVNr entfaellt).
 *   d) Drei OwnerPIN-Objekte (Admin/Operator/User), Auswahl per P2.
 *   e) CHANGE-Kommando, einmalig pro PIN, in Reihenfolge
 *      PIN1 -> PIN2 -> PIN3.
 *   f) CREDIT/DEBIT/BALANCE mit Over-/Underflow (Euro+Cent),
 *      STATUS, AGE18 (mit aktuellem Datum als Parameter),
 *      UNLOCK per PUK mit 10 Versuchen.
 *   h) Cent-Praezision (in EUR/CENT zerlegt) und FIFO-Logbuch
 *      der letzten 10 Transaktionen (PIN3-geschuetzt).
 *
 * INS-Bytes meiden 0x60-0x6F, 0x90-0x9F und 0xC2 (siehe FAQ S.10).
 *********************************************************/

package com.gieseckedevrient.applets.myfirst;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class MyFirstApplet extends Applet {

    // ===================== INS-Bytes (CLA immer 0x00) =====================
    // ISO 7816-4 Standard-INS
    private static final byte INS_VERIFY  = (byte) 0x20;
    private static final byte INS_READ    = (byte) 0xB6;   // READ BINARY
    private static final byte INS_MODIFY  = (byte) 0xD6;   // UPDATE BINARY
    // Custom-INS
    private static final byte INS_AGE18   = (byte) 0x18;
    private static final byte INS_CHANGE  = (byte) 0x24;
    private static final byte INS_CREDIT  = (byte) 0x30;
    private static final byte INS_DEBIT   = (byte) 0x40;
    private static final byte INS_BALANCE = (byte) 0x50;
    private static final byte INS_UNLOCK  = (byte) 0x78;
    private static final byte INS_LOG     = (byte) 0x76;
    private static final byte INS_STATUS  = (byte) 0xF2;

    private static final short SW_VERIFY_FAIL_BASE = (short) 0x63C0;

    // ===================== PIN/PUK-Parameter =====================
    private static final byte PIN_TRY_LIMIT = (byte) 3;
    private static final byte PIN_SIZE      = (byte) 4;
    private static final byte PUK_TRY_LIMIT = (byte) 10;
    private static final byte PUK_SIZE      = (byte) 8;

    // P2-Werte zur Auswahl der PIN
    private static final byte P2_PIN1 = (byte) 0x01;   // Admin    (Ausgabestelle)
    private static final byte P2_PIN2 = (byte) 0x02;   // Operator (Ladestation)
    private static final byte P2_PIN3 = (byte) 0x03;   // User     (Karteninhaber)

    // ===================== Feldlaengen / Limits =====================
    private static final short MAX_EUROS      = (short) 9999;  // max EUR 9999,99
    private static final short MAX_CENTS      = (short) 99;
    private static final short FIELD_NAME_MAX = (short) 30;
    private static final short FIELD_DATE_LEN = (short) 8;     // DDMMYYYY ASCII
    private static final short AMOUNT_LEN     = (short) 3;     // EUR_hi EUR_lo CENT

    // ===================== Logbuch =====================
    private static final short LOG_ENTRIES     = (short) 10;
    private static final short LOG_ENTRY_BYTES = (short) 4;    // type + 2 EUR + 1 CENT
    private static final short LOG_BUF_BYTES   = (short) 40;
    private static final byte  TX_CREDIT       = (byte) 0x01;
    private static final byte  TX_DEBIT        = (byte) 0x02;

    // ===================== Benutzerdaten (W01.4 c) =====================
    private byte[]  firstName;
    private short   firstNameLen;
    private byte[]  lastName;
    private short   lastNameLen;
    private byte[]  birthDate;            // 8 Byte DDMMYYYY ASCII
    private boolean userDataSet;

    // ===================== PIN-Objekte + Statusflags (W01.4 d,e) =====================
    private OwnerPIN pin1, pin2, pin3, puk;
    private boolean  pin1Changed, pin2Changed, pin3Changed;
    private boolean  cardBlocked;         // nach PUK-Erschoepfung gesetzt

    // ===================== Guthaben (W01.4 f) =====================
    // EUR und CENT getrennt, da 999.999 Cents nicht in short passen.
    private short   balanceEuros;
    private short   balanceCents;
    // Debit nur erlaubt, wenn Age18 in dieser Session true zurueckgegeben hat.
    private boolean ageVerified;

    // ===================== Logbuch-State (W01.4 h) =====================
    private byte[] logBuf;
    private short  logHead;     // naechster Schreibindex (0..LOG_ENTRIES-1)
    private short  logCount;    // Anzahl gueltiger Eintraege (0..LOG_ENTRIES)

    // =============================================================
    // Lifecycle
    // =============================================================
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MyFirstApplet(bArray, bOffset, bLength);
    }

    private MyFirstApplet(byte[] bArray, short bOffset, byte bLength) {
        // Globale Felder (Anleitung S.1: keine Garbage Collection)
        firstName = new byte[FIELD_NAME_MAX];
        lastName  = new byte[FIELD_NAME_MAX];
        birthDate = new byte[FIELD_DATE_LEN];

        pin1 = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        pin2 = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        pin3 = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        puk  = new OwnerPIN(PUK_TRY_LIMIT, PUK_SIZE);

        // Default: alle PINs "0000", PUK "00000000" (ASCII)
        byte[] zeros = { (byte) '0', (byte) '0', (byte) '0', (byte) '0',
                         (byte) '0', (byte) '0', (byte) '0', (byte) '0' };
        pin1.update(zeros, (short) 0, PIN_SIZE);
        pin2.update(zeros, (short) 0, PIN_SIZE);
        pin3.update(zeros, (short) 0, PIN_SIZE);
        puk.update(zeros, (short) 0, PUK_SIZE);

        logBuf = new byte[LOG_BUF_BYTES];

        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    // =============================================================
    // APDU Dispatcher
    // =============================================================
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            resetAllPinAuth();
            return;
        }
        // Karte permanent gesperrt nach 10 falschen PUK-Eingaben
        if (cardBlocked) {
            ISOException.throwIt(ISO7816.SW_FILE_INVALID);
        }
        byte[] buf = apdu.getBuffer();
        // CLA muss 0x00 sein (Anleitung S.2 + FAQ S.10)
        if (buf[ISO7816.OFFSET_CLA] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_VERIFY:  verifyPin(apdu);      break;
            case INS_CHANGE:  changePin(apdu);      break;
            case INS_READ:    readUserData(apdu);   break;
            case INS_MODIFY:  modifyUserData(apdu); break;
            case INS_CREDIT:  credit(apdu);         break;
            case INS_DEBIT:   debit(apdu);          break;
            case INS_BALANCE: balance(apdu);        break;
            case INS_STATUS:  status(apdu);         break;
            case INS_AGE18:   age18(apdu);          break;
            case INS_UNLOCK:  unlock(apdu);         break;
            case INS_LOG:     readLog(apdu);        break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void resetAllPinAuth() {
        pin1.reset();
        pin2.reset();
        pin3.reset();
        puk.reset();
        ageVerified = false;
    }

    // =============================================================
    // Hilfsmethoden
    // =============================================================

    /** Waehlt das OwnerPIN-Objekt anhand des P2-Bytes. */
    private OwnerPIN selectPin(byte p2) {
        switch (p2) {
            case P2_PIN1: return pin1;
            case P2_PIN2: return pin2;
            case P2_PIN3: return pin3;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                return null;
        }
    }

    /**
     * Liest die in Lc angekuendigte Anzahl Bytes vollstaendig in den APDU-Buffer.
     * expectedLen != -1: zusaetzliche Pruefung auf exakte Laenge.
     */
    private short receiveExact(APDU apdu, short expectedLen) {
        byte[] buf = apdu.getBuffer();
        short lc = (short) (buf[ISO7816.OFFSET_LC] & 0x00FF);
        if (lc != apdu.setIncomingAndReceive()) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        if (expectedLen != (short) -1 && lc != expectedLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        return lc;
    }

    private short findByte(byte[] b, short start, short end, byte target) {
        for (short i = start; i < end; i++) {
            if (b[i] == target) return i;
        }
        return (short) -1;
    }

    private boolean allPinsChanged() {
        return pin1Changed && pin2Changed && pin3Changed;
    }

    private short asciiToShort(byte[] src, short off, short len) {
        short n = 0;
        short digit;
        for (short i = 0; i < len; i++) {
            digit = (short) (src[(short) (off + i)] - (byte) '0');
            n = (short) (n * (short) 10);
            n = (short) (n + digit);
        }
        return n;
    }

    private short logOffset(short index) {
        switch (index) {
            case 0: return (short) 0;
            case 1: return (short) 4;
            case 2: return (short) 8;
            case 3: return (short) 12;
            case 4: return (short) 16;
            case 5: return (short) 20;
            case 6: return (short) 24;
            case 7: return (short) 28;
            case 8: return (short) 32;
            default: return (short) 36;
        }
    }

    // =============================================================
    // VERIFY (W01.4 d) - P2 = PIN-Auswahl, Daten = PIN
    // =============================================================
    private void verifyPin(APDU apdu) {
        byte[]   buf = apdu.getBuffer();
        OwnerPIN p   = selectPin(buf[ISO7816.OFFSET_P2]);
        receiveExact(apdu, PIN_SIZE);
        if (!p.check(buf, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
            // ISO 7816-4: 0x63Cx mit x = verbleibende Versuche
            short remaining = (short) p.getTriesRemaining();
            ISOException.throwIt((short) (SW_VERIFY_FAIL_BASE + remaining));
        }
    }

    // =============================================================
    // CHANGE (W01.4 e) - einmalig pro PIN, in Reihenfolge PIN1 -> PIN2 -> PIN3
    // =============================================================
    private void changePin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte   p2  = buf[ISO7816.OFFSET_P2];
        receiveExact(apdu, PIN_SIZE);
        switch (p2) {
            case P2_PIN1:
                if (pin1Changed) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                if (!pin1.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                pin1.update(buf, ISO7816.OFFSET_CDATA, PIN_SIZE);
                pin1Changed = true;
                break;
            case P2_PIN2:
                // PIN1 muss vorher geaendert sein, und PIN2 nur einmal
                if (!pin1Changed || pin2Changed) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                if (!pin2.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                pin2.update(buf, ISO7816.OFFSET_CDATA, PIN_SIZE);
                pin2Changed = true;
                break;
            case P2_PIN3:
                if (!pin2Changed || pin3Changed) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                if (!pin3.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
                pin3.update(buf, ISO7816.OFFSET_CDATA, PIN_SIZE);
                pin3Changed = true;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // =============================================================
    // MODIFY Benutzerdaten (W01.4 b,c) - benoetigt PIN1
    // Daten: <firstName>0xFF<lastName>0xFF<DDMMYYYY>0xFF
    // Laengen werden geprueft -> 6A 80 statt 6F 00 wie MyFirst.
    // =============================================================
    private void modifyUserData(APDU apdu) {
        if (!pin1.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf  = apdu.getBuffer();
        short  lc   = receiveExact(apdu, (short) -1);
        short start = (short) (ISO7816.OFFSET_CDATA & 0x00FF);
        short end   = (short) (start + lc);

        // Vorname
        short sep1 = findByte(buf, start, end, (byte) 0xFF);
        if (sep1 < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short fLen = (short) (sep1 - start);
        if (fLen == 0 || fLen > FIELD_NAME_MAX) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        // Nachname
        short lStart = (short) (sep1 + 1);
        short sep2   = findByte(buf, lStart, end, (byte) 0xFF);
        if (sep2 < 0) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        short lLen = (short) (sep2 - lStart);
        if (lLen == 0 || lLen > FIELD_NAME_MAX) ISOException.throwIt(ISO7816.SW_WRONG_DATA);

        // Geburtsdatum: exakt 8 ASCII-Ziffern + 0xFF
        short dStart = (short) (sep2 + 1);
        if ((short) (dStart + FIELD_DATE_LEN) >= end) ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        if (buf[(short) (dStart + FIELD_DATE_LEN)] != (byte) 0xFF) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        for (short i = 0; i < FIELD_DATE_LEN; i++) {
            byte b = buf[(short) (dStart + i)];
            if (b < (byte) '0' || b > (byte) '9') ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Erst nach erfolgreicher Pruefung schreiben
        Util.arrayCopyNonAtomic(buf, start,  firstName, (short) 0, fLen);
        firstNameLen = fLen;
        Util.arrayCopyNonAtomic(buf, lStart, lastName,  (short) 0, lLen);
        lastNameLen = lLen;
        Util.arrayCopyNonAtomic(buf, dStart, birthDate, (short) 0, FIELD_DATE_LEN);
        userDataSet = true;
    }

    // =============================================================
    // READ Benutzerdaten - benoetigt PIN1 oder PIN2
    // =============================================================
    private void readUserData(APDU apdu) {
        if (!pin1.isValidated() && !pin2.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!userDataSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        short  off = 0;
        Util.arrayCopyNonAtomic(firstName, (short) 0, buf, off, firstNameLen);
        off = (short) (off + firstNameLen);
        buf[off++] = (byte) 0xFF;
        Util.arrayCopyNonAtomic(lastName, (short) 0, buf, off, lastNameLen);
        off = (short) (off + lastNameLen);
        buf[off++] = (byte) 0xFF;
        Util.arrayCopyNonAtomic(birthDate, (short) 0, buf, off, FIELD_DATE_LEN);
        off = (short) (off + FIELD_DATE_LEN);
        buf[off++] = (byte) 0xFF;

        apdu.setOutgoing();
        apdu.setOutgoingLength(off);
        apdu.sendBytes((short) 0, off);
    }

    // =============================================================
    // CREDIT (W01.4 f) - PIN2, alle 3 PINs muessen geaendert sein
    // Daten: 3 Byte = [EUR_hi, EUR_lo, CENT]
    // =============================================================
    private void credit(APDU apdu) {
        if (!pin2.isValidated())   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (!allPinsChanged())     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, AMOUNT_LEN);

        short addEuros = Util.makeShort(buf[ISO7816.OFFSET_CDATA],
                                        buf[(short) (ISO7816.OFFSET_CDATA + 1)]);
        short addCents = (short) buf[(short) (ISO7816.OFFSET_CDATA + 2)];
        if (addEuros < (short) 0 || addCents < (short) 0 || addCents > MAX_CENTS) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Cent-Addition mit Uebertrag
        short newCents = (short) (balanceCents + addCents);
        short carry = (short) 0;
        if (newCents >= (short) 100) {
            carry = (short) 1;
        }
        if (carry == (short) 1) newCents = (short) (newCents - (short) 100);
        short newEuros = (short) (balanceEuros + addEuros + carry);

        // Overflow: > 9999,99 EUR
        if (newEuros > MAX_EUROS || (newEuros == MAX_EUROS && newCents > MAX_CENTS)) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        balanceEuros = newEuros;
        balanceCents = newCents;
        logTransaction(TX_CREDIT, addEuros, (byte) addCents);
    }

    // =============================================================
    // DEBIT (W01.4 f) - PIN3, alle 3 PINs geaendert, Alter >= 18 per Age18 bestaetigt
    // =============================================================
    private void debit(APDU apdu) {
        if (!pin3.isValidated())   ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (!allPinsChanged())     ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        // Bezahlfunktion voruebergehend blockiert, bis Age18 in dieser Session true ergab.
        if (!ageVerified)          ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, AMOUNT_LEN);

        short subEuros = Util.makeShort(buf[ISO7816.OFFSET_CDATA],
                                        buf[(short) (ISO7816.OFFSET_CDATA + 1)]);
        short subCents = (short) buf[(short) (ISO7816.OFFSET_CDATA + 2)];
        if (subEuros < (short) 0 || subCents < (short) 0 || subCents > MAX_CENTS) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Cent-Subtraktion mit Borrow
        short newCents = (short) (balanceCents - subCents);
        short borrow = (short) 0;
        if (newCents < (short) 0) {
            borrow = (short) 1;
        }
        if (borrow == (short) 1) newCents = (short) (newCents + (short) 100);
        short newEuros = (short) (balanceEuros - subEuros - borrow);

        if (newEuros < (short) 0) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        balanceEuros = newEuros;
        balanceCents = newCents;
        logTransaction(TX_DEBIT, subEuros, (byte) subCents);
    }

    // =============================================================
    // BALANCE (ohne PIN) - Rueckgabe: 3 Byte [EUR_hi, EUR_lo, CENT]
    // =============================================================
    private void balance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        Util.setShort(buf, (short) 0, balanceEuros);
        buf[2] = (byte) balanceCents;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 3);
        apdu.sendBytes((short) 0, (short) 3);
    }

    // =============================================================
    // STATUS (ohne PIN) - 9 Byte Statusvektor
    //   [pin1Changed, pin2Changed, pin3Changed,
    //    triesPIN1, triesPIN2, triesPIN3, triesPUK,
    //    userDataSet, cardBlocked]
    // =============================================================
    private void status(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        buf[0] = (byte) 0;
        if (pin1Changed) buf[0] = (byte) 1;
        buf[1] = (byte) 0;
        if (pin2Changed) buf[1] = (byte) 1;
        buf[2] = (byte) 0;
        if (pin3Changed) buf[2] = (byte) 1;
        buf[3] = pin1.getTriesRemaining();
        buf[4] = pin2.getTriesRemaining();
        buf[5] = pin3.getTriesRemaining();
        buf[6] = puk.getTriesRemaining();
        buf[7] = (byte) 0;
        if (userDataSet) buf[7] = (byte) 1;
        buf[8] = (byte) 0;
        if (cardBlocked) buf[8] = (byte) 1;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 9);
        apdu.sendBytes((short) 0, (short) 9);
    }

    // =============================================================
    // AGE18 (W01.4 f) - PIN1 oder PIN2 - Daten: heutiges Datum DDMMYYYY
    // Rueckgabe: 1 Byte, 0x01 wenn Alter >= 18, sonst 0x00.
    // =============================================================
    private void age18(APDU apdu) {
        if (!pin1.isValidated() && !pin2.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        if (!userDataSet) ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, FIELD_DATE_LEN);
        for (short i = 0; i < FIELD_DATE_LEN; i++) {
            byte b = buf[(short) (ISO7816.OFFSET_CDATA + i)];
            if (b < (byte) '0' || b > (byte) '9') ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
        short tD = asciiToShort(buf,             ISO7816.OFFSET_CDATA,        (short) 2);
        short tM = asciiToShort(buf, (short) (ISO7816.OFFSET_CDATA + 2),      (short) 2);
        short tY = asciiToShort(buf, (short) (ISO7816.OFFSET_CDATA + 4),      (short) 4);
        short bD = asciiToShort(birthDate, (short) 0, (short) 2);
        short bM = asciiToShort(birthDate, (short) 2, (short) 2);
        short bY = asciiToShort(birthDate, (short) 4, (short) 4);

        short age = (short) (tY - bY);
        // Geburtstag in diesem Jahr noch nicht erreicht -> ein Jahr abziehen
        if (tM < bM || (tM == bM && tD < bD)) age = (short) (age - (short) 1);

        if (age >= (short) 18) {
            buf[0] = (byte) 0x01;
            ageVerified = true;
        } else {
            buf[0] = (byte) 0x00;
            ageVerified = false;
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        apdu.sendBytes((short) 0, (short) 1);
    }

    // =============================================================
    // UNLOCK (W01.4 f) - PUK + neue PIN3
    // Daten: 8 Byte PUK + 4 Byte neue PIN3 = 12 Byte
    // 10 falsche Versuche -> Karte irreversibel gesperrt.
    // =============================================================
    private void unlock(APDU apdu) {
        if (pin3.getTriesRemaining() != 0) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, (short) (PUK_SIZE + PIN_SIZE));
        if (!puk.check(buf, ISO7816.OFFSET_CDATA, PUK_SIZE)) {
            if (puk.getTriesRemaining() == 0) {
                cardBlocked = true;
                ISOException.throwIt(ISO7816.SW_FILE_INVALID);
            }
            short remaining = (short) puk.getTriesRemaining();
            ISOException.throwIt((short) (SW_VERIFY_FAIL_BASE + remaining));
        }
        // PUK korrekt -> PIN3 neu setzen (resettet auch deren Versuchszaehler)
        pin3.update(buf, (short) (ISO7816.OFFSET_CDATA + PUK_SIZE), PIN_SIZE);
    }

    // =============================================================
    // LOG (W01.4 h) - PIN3 - FIFO der letzten 10 Transaktionen
    // Eintrag: [type (0x01=Credit/0x02=Debit), EUR_hi, EUR_lo, CENT]
    // =============================================================
    private void readLog(APDU apdu) {
        if (!pin3.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        byte[] buf = apdu.getBuffer();
        short  out = 0;
        // Buffer noch nicht voll -> start bei 0; sonst aelteste (=logHead)
        short start = (short) 0;
        if (logCount >= LOG_ENTRIES) {
            start = logHead;
        }
        for (short i = 0; i < logCount; i++) {
            short idx = (short) (start + i);
            if (idx >= LOG_ENTRIES) idx = (short) (idx - LOG_ENTRIES);
            Util.arrayCopyNonAtomic(logBuf, logOffset(idx), buf, out, LOG_ENTRY_BYTES);
            out = (short) (out + LOG_ENTRY_BYTES);
        }
        apdu.setOutgoing();
        apdu.setOutgoingLength(out);
        apdu.sendBytes((short) 0, out);
    }

    private void logTransaction(byte type, short euros, byte cents) {
        short off = logOffset(logHead);
        logBuf[off]                = type;
        Util.setShort(logBuf, (short) (off + 1), euros);
        logBuf[(short) (off + 3)]  = cents;
        logHead = (short) (logHead + (short) 1);
        if (logHead >= LOG_ENTRIES) logHead = (short) 0;
        if (logCount < LOG_ENTRIES) logCount++;
    }
}
