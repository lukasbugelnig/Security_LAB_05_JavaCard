/**********************************************************
 * Project:  Java Card Applet Samples - Electronic Purse
 * File:     PurseApplet.java
 *
 * System Security Lab SS 2026 (W01)
 *
 * Schritt 1: Auf-/Abbuchen einer Geldboerse.
 *   - Refactoring der MyFirst-Benutzerdaten (Vorname, Nachname,
 *     Geburtsdatum), SVNr entfaellt.
 *   - Eine einzige PIN (default "0000") als Zugriffsschutz.
 *   - CREDIT, DEBIT, BALANCE inkl. Over-/Underflow.
 *
 * Spaetere Erweiterungen (siehe weitere Commits): 3-PIN-
 * Management, CHANGE, Age18, PUK-Unlock, Logbuch.
 *********************************************************/

package com.gieseckedevrient.applets.purse;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;

public class PurseApplet extends Applet {

    // ===================== INS-Bytes (CLA immer 0x00) =====================
    private static final byte INS_VERIFY  = (byte) 0x20;   // ISO 7816-4
    private static final byte INS_READ    = (byte) 0xB6;   // READ BINARY
    private static final byte INS_MODIFY  = (byte) 0xD6;   // UPDATE BINARY
    // Custom-INS (meiden: 0x60-0x6F, 0x90-0x9F, 0xC2 - siehe FAQ S.10)
    private static final byte INS_CREDIT  = (byte) 0x30;
    private static final byte INS_DEBIT   = (byte) 0x40;
    private static final byte INS_BALANCE = (byte) 0x50;

    // ===================== PIN-Parameter =====================
    private static final byte PIN_TRY_LIMIT = (byte) 3;
    private static final byte PIN_SIZE      = (byte) 4;

    // ===================== Feldlaengen / Limits =====================
    private static final short MAX_EUROS      = (short) 9999;  // max EUR 9999,99
    private static final short MAX_CENTS      = (short) 99;
    private static final short FIELD_NAME_MAX = (short) 30;
    private static final short FIELD_DATE_LEN = (short) 8;     // DDMMYYYY ASCII
    private static final short AMOUNT_LEN     = (short) 3;     // EUR_hi EUR_lo CENT

    // ===================== Benutzerdaten (W01.4c: aufgespalten) =====================
    private byte[]  firstName;
    private short   firstNameLen;
    private byte[]  lastName;
    private short   lastNameLen;
    private byte[]  birthDate;            // 8 Byte DDMMYYYY ASCII
    private boolean userDataSet;

    // ===================== PIN =====================
    // Vorerst eine einzige PIN (default "0000"). Wird im naechsten Commit
    // durch drei PINs mit P2-Auswahl ersetzt (W01.4 d).
    private OwnerPIN pin;

    // ===================== Guthaben (Euros + Cents, da > 32767 Cents) =====================
    private short balanceEuros;
    private short balanceCents;

    // =============================================================
    // Lifecycle
    // =============================================================
    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PurseApplet(bArray, bOffset, bLength);
    }

    private PurseApplet(byte[] bArray, short bOffset, byte bLength) {
        // Felder global anlegen (keine GC -> siehe Anleitung S.1)
        firstName = new byte[FIELD_NAME_MAX];
        lastName  = new byte[FIELD_NAME_MAX];
        birthDate = new byte[FIELD_DATE_LEN];

        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        byte[] zeros = { (byte) '0', (byte) '0', (byte) '0', (byte) '0' };
        pin.update(zeros, (short) 0, PIN_SIZE);

        register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    // =============================================================
    // APDU Dispatcher
    // =============================================================
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            pin.reset();
            return;
        }
        byte[] buf = apdu.getBuffer();
        // CLA muss 0x00 sein (siehe Anleitung + FAQ S.10)
        if (buf[ISO7816.OFFSET_CLA] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        switch (buf[ISO7816.OFFSET_INS]) {
            case INS_VERIFY:  verifyPin(apdu);      break;
            case INS_READ:    readUserData(apdu);   break;
            case INS_MODIFY:  modifyUserData(apdu); break;
            case INS_CREDIT:  credit(apdu);         break;
            case INS_DEBIT:   debit(apdu);          break;
            case INS_BALANCE: balance(apdu);        break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // =============================================================
    // Hilfsmethoden
    // =============================================================

    /**
     * Liest die in Lc angekuendigte Anzahl Bytes vollstaendig in den APDU-Buffer.
     * Wenn expectedLen != -1, wird zusaetzlich gegen diesen Wert geprueft.
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

    // =============================================================
    // VERIFY (Daten = 4-Byte-PIN)
    // =============================================================
    private void verifyPin(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, PIN_SIZE);
        if (!pin.check(buf, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
            // ISO 7816-4: 0x63Cx mit x = verbleibende Versuche
            short remaining = (short) (pin.getTriesRemaining() & 0x0F);
            ISOException.throwIt((short) (0x63C0 | remaining));
        }
    }

    // =============================================================
    // MODIFY Benutzerdaten
    // Daten: <firstName>0xFF<lastName>0xFF<DDMMYYYY>0xFF
    // Anders als bei MyFirstApplet: Laengen werden vor dem Commit
    // geprueft - kein Buffer-Overrun moeglich (W01.4 b).
    // =============================================================
    private void modifyUserData(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
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
    // READ Benutzerdaten
    // =============================================================
    private void readUserData(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        if (!userDataSet)       ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);

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
    // CREDIT (Auf-Buchen)
    // Daten: 3 Byte = [EUR_hi, EUR_lo, CENT]
    // Overflow: Guthaben darf 9999,99 EUR nicht ueberschreiten.
    // =============================================================
    private void credit(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, AMOUNT_LEN);

        short addEuros = (short) (((buf[ISO7816.OFFSET_CDATA]     & 0xFF) << 8)
                                   | (buf[ISO7816.OFFSET_CDATA + 1] & 0xFF));
        short addCents = (short) (buf[ISO7816.OFFSET_CDATA + 2] & 0xFF);
        if (addEuros < 0 || addCents < 0 || addCents > 99) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Cent-Addition mit Uebertrag
        short newCents = (short) (balanceCents + addCents);
        short carry    = (newCents >= 100) ? (short) 1 : (short) 0;
        if (carry == 1) newCents = (short) (newCents - 100);
        short newEuros = (short) (balanceEuros + addEuros + carry);

        // Overflow-Check
        if (newEuros > MAX_EUROS || (newEuros == MAX_EUROS && newCents > MAX_CENTS)) {
            ISOException.throwIt(ISO7816.SW_FILE_FULL);
        }
        balanceEuros = newEuros;
        balanceCents = newCents;
    }

    // =============================================================
    // DEBIT (Ab-Buchen)
    // Daten: 3 Byte = [EUR_hi, EUR_lo, CENT]
    // Underflow: Guthaben darf nicht negativ werden.
    // =============================================================
    private void debit(APDU apdu) {
        if (!pin.isValidated()) ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

        byte[] buf = apdu.getBuffer();
        receiveExact(apdu, AMOUNT_LEN);

        short subEuros = (short) (((buf[ISO7816.OFFSET_CDATA]     & 0xFF) << 8)
                                   | (buf[ISO7816.OFFSET_CDATA + 1] & 0xFF));
        short subCents = (short) (buf[ISO7816.OFFSET_CDATA + 2] & 0xFF);
        if (subEuros < 0 || subCents < 0 || subCents > 99) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        // Cent-Subtraktion mit Borrow
        short newCents = (short) (balanceCents - subCents);
        short borrow   = (newCents < 0) ? (short) 1 : (short) 0;
        if (borrow == 1) newCents = (short) (newCents + 100);
        short newEuros = (short) (balanceEuros - subEuros - borrow);

        if (newEuros < 0) {
            ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
        }
        balanceEuros = newEuros;
        balanceCents = newCents;
    }

    // =============================================================
    // BALANCE - Rueckgabe: 3 Byte [EUR_hi, EUR_lo, CENT]
    // (ohne PIN-Verifikation, wie in der Anleitung gefordert)
    // =============================================================
    private void balance(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        buf[0] = (byte) ((balanceEuros >> 8) & 0xFF);
        buf[1] = (byte) (balanceEuros & 0xFF);
        buf[2] = (byte) (balanceCents & 0xFF);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 3);
        apdu.sendBytes((short) 0, (short) 3);
    }
}
